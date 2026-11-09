"""S6.3c FastAPI profile contracts; Docker is mocked, not a live integration."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from securitylab.cli import main
from securitylab.fastapi_probe import ASGI_LAUNCHER, fastapi_probe_snapshot
from securitylab.http_runner import FastAPIHTTPDockerBroker
from securitylab.job_contract import parse_job
from securitylab.policy import PolicyError
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot
from securitylab.storage import Store
from test_http_probe import FakeHTTPDocker, FakeAttachment, IMAGE, response

FAST_IMAGE='sha256:'+'f'*64

class FakeFastAPIDocker(FakeHTTPDocker):
    missing_image=False
    bad_label=False
    bad_runtime_image=False

    def __call__(self, argv, cwd, limits, **kwargs):
        args = argv[3:] if argv[1:2] == ['--host'] else argv[1:]
        if args[:2] == ['image','inspect'] and args[-1] == 'securitylab-fastapi:local':
            self.calls.append((args,kwargs))
            if self.missing_image:
                return response('',code=1)
            label = 'wrong' if self.bad_label else 'fastapi-s63c-v1'
            return response(json.dumps([{'Id':FAST_IMAGE,'Config':{'Volumes':None,
                        'Labels':{'org.securitylab.profile':label}}}]))
        r=super().__call__(argv,cwd,limits,**kwargs)
        if args[0]=='inspect' and '--format' not in args:
            name=args[1]
            recorded=self.containers[name]
            selected=next(value for value in recorded if isinstance(value, str) and value.startswith('sha256:'))
            data=json.loads(r.stdout)
            if self.bad_runtime_image and '--network-alias' in recorded:
                selected=IMAGE
            data[0]['Config']['Image']=selected
            return response(json.dumps(data))
        return r


class FastAPIProfileTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        project=self.root/'sample';project.mkdir()
        self.entry=project/'main.py'
        self.entry.write_text('from fastapi import FastAPI\napp = FastAPI()\n',encoding='utf-8')
        (project/'pyproject.toml').write_text('[project]\nname="x"\nversion="0.1"\n',encoding='utf-8')
        self.store=Store(self.root/'state');self.addCleanup(self.store.close)
        pid=add_project(self.store,project,'sample')['id']
        self.sid=create_snapshot(self.store,pid)['snapshot_id']
        self.fake=FakeFastAPIDocker()

    def factory(self, cwd):
        return FastAPIHTTPDockerBroker(cwd,executor=self.fake,attachment_cls=FakeAttachment)

    def run_probe(self, **kw):
        return fastapi_probe_snapshot(self.store,self.sid,'main.py', ['/health=200','/missing=404'],
                                     execute=True,broker_factory=self.factory,**kw)

    def test_baked_images_are_separately_pinned(self):
        r=self.run_probe()
        self.assertEqual(r['status'],'HTTP_CHECKS_PASSED',r)
        self.assertEqual(r['security_verdict'],'NOT_EVALUATED')
        self.assertIsNone(r['finding_status'])
        self.assertEqual(r['image_id'],IMAGE)
        self.assertEqual(r['target_image_id'],FAST_IMAGE)
        self.assertEqual(r['cleanup'],'PASS')
        names={args[args.index('--name')+1]:args for args,_ in self.fake.calls if args[0]=='create'}
        target=[a for a in names.values() if '--network-alias' in a][0]
        verifier=[a for a in names.values() if '--network-alias' not in a][0]
        self.assertEqual(target[target.index('--entrypoint')+2],FAST_IMAGE)
        self.assertIn(IMAGE,verifier)
        for args in (target,verifier):
            self.assertNotIn('--publish',args)
            self.assertNotIn('--volume',args)
            self.assertIn('--read-only',args)
        source=parse_job(FakeAttachment.inputs[-1][1])['files']
        self.assertIn('project.py',source)
        self.assertEqual(source['task.py'],ASGI_LAUNCHER)
        self.assertNotIn('pip install',source['task.py'])

    def test_unpinned_or_mislabelled_image_fails_closed(self):
        for field in ('missing_image','bad_label'):
            with self.subTest(field=field):
                fake=FakeFastAPIDocker()
                setattr(fake,field,True)
                self.fake=fake
                r=self.run_probe()
                self.assertEqual(r['status'],'BLOCKED',r)
                self.assertEqual(r['security_verdict'],'NOT_EVALUATED')
                self.assertFalse(any(args[0]=='create' for args,_ in fake.calls))

    def test_changed_target_image_rejected_before_execution(self):
        self.fake.bad_runtime_image=True
        r=self.run_probe()
        self.assertEqual(r['status'],'BLOCKED',r)
        self.assertEqual(r['security_verdict'],'NOT_EVALUATED')
        self.assertEqual(r.get('cleanup'),None)

    def test_failure_or_missing_observation_is_not_fixed(self):
        self.fake.status_override=401
        r=self.run_probe()
        self.assertEqual(r['status'],'HTTP_CHECKS_FAILED')
        self.assertEqual(r['security_verdict'],'NOT_EVALUATED')
        self.fake.verifier_problem='unreachable'
        r=self.run_probe()
        self.assertEqual(r['status'],'BLOCKED')

    def test_cleanup_failure_blocks(self):
        self.fake.cleanup_failure=True
        r=self.run_probe()
        self.assertEqual(r['status'],'BLOCKED')
        self.assertEqual(r['security_verdict'],'NOT_EVALUATED')

    def test_opt_in_rejected_without_docker(self):
        with self.assertRaises(PolicyError):
            fastapi_probe_snapshot(self.store,self.sid,'main.py',['/health=200'])
        with self.assertRaises(PolicyError):
            fastapi_probe_snapshot(self.store,self.sid,'main.py',[],execute=True)
        self.assertEqual(self.fake.calls,[])

    def test_tampered_snapshot_blocked_without_docker(self):
        path=self.store.root/'snapshots'/self.sid/'workspace'/'main.py'
        path.write_text('print("compromised")',encoding='utf-8')
        with self.assertRaises(PolicyError):
            self.run_probe()
        self.assertEqual(self.fake.calls,[])

    def test_entry_path_traversal_rejected_without_docker(self):
        with self.assertRaises(PolicyError):
            fastapi_probe_snapshot(self.store,self.sid,'../main.py',['/health=200'],execute=True,
                                   broker_factory=self.factory)
        self.assertEqual(self.fake.calls,[])

    def test_verifier_receipt_mismatch_blocked(self):
        self.fake.verifier_problem='bad-nonce'
        r=self.run_probe()
        self.assertEqual(r['status'],'BLOCKED')
        self.assertEqual(r['security_verdict'],'NOT_EVALUATED')

    def test_cli_without_execute_and_scan_still_blocked(self):
        out=io.StringIO();err=io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=main(['--state',str(self.store.root),'repo','fastapi-probe',self.sid,
                       '--entry','main.py','--expect','/health=200'])
        self.assertEqual(code,2)
        self.assertIn('requires explicit --execute',err.getvalue())
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=main(['--state',str(self.store.root),'scan',str(self.root)])
        self.assertEqual(code,2)
        self.assertIn('BLOCKED',err.getvalue())

if __name__=='__main__':
    unittest.main()
