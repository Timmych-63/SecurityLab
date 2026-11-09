"""S6.3d contracts: bounded packages and independent HTTP verification.

Docker is simulated in these tests. No untrusted Python is executed on host.
"""
import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from securitylab.cli import main
from securitylab.container_worker import _write_job_files
from securitylab.http_runner import FastAPIHTTPDockerBroker
from securitylab.job_contract import job_bytes, parse_job
from securitylab.package_probe import package_probe_snapshot
from securitylab.policy import PolicyError
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot
from securitylab.storage import Store
from test_fastapi_probe import FakeFastAPIDocker, FAST_IMAGE
from test_http_probe import FakeAttachment, IMAGE

ROOT = Path(__file__).resolve().parents[1]


class PackageContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'repo'
        shutil.copytree(ROOT / 'examples/s6_repos/python_fastapi_package', self.project)
        self.store = Store(self.root / 'state')
        self.addCleanup(self.store.close)
        self.sid = self.snapshot()
        self.fake = FakeFastAPIDocker()

    def snapshot(self):
        pid = add_project(self.store, self.project, 'fixture')['id']
        return create_snapshot(self.store, pid)['snapshot_id']

    def factory(self, cwd):
        return FastAPIHTTPDockerBroker(cwd, executor=self.fake, attachment_cls=FakeAttachment)

    def probe(self, *, entry='app/main.py', service='.', execute=True, checks=None):
        return package_probe_snapshot(self.store, self.sid, entry,
                        checks or ['/health=200', '/__missing__=404'], service=service,
                        execute=execute, broker_factory=self.factory)

    def test_v2_allows_nested_sources_without_weakening_v1(self):
        files = {'task.py':'pass', 'app/__init__.py':'', 'app/main.py':'app=True'}
        with self.assertRaises(PolicyError):
            job_bytes(files)
        packet = job_bytes(files, schema_version=2)
        self.assertEqual(parse_job(packet)['files'],files)
        self.assertEqual(parse_job(packet)['schema_version'],2)
        with self.assertRaises(PolicyError):
            job_bytes({'task.py':'pass'}, schema_version=3)

    def test_worker_stages_nested_modules_only_as_files(self):
        files={'task.py':'pass', 'app/__init__.py':'', 'app/routes.py':'greeting="ok"'}
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            _write_job_files(root,parse_job(job_bytes(files,schema_version=2)))
            self.assertEqual((root/'app'/'routes.py').read_text(), 'greeting="ok"')
            self.assertEqual((root/'task.py').read_text(), 'pass')
            self.assertEqual(sorted(x.relative_to(root).as_posix() for x in root.rglob('*.py')),
                             ['app/__init__.py','app/routes.py','task.py'])

    def test_v2_rejects_traversal_windows_paths_and_case_collisions(self):
        bad = ('../evil.py', '/tmp/m.py', 'app/../x.py', 'app\\x.py',
               'app//x.py', '.hidden/m.py', 'app/x.txt', 'app/v1/x.py/part.py',
               'app/v1/v2/v3/v4/v5/x.py', '__pycache__/x.py')
        for name in bad:
            with self.subTest(name=name), self.assertRaises(PolicyError):
                job_bytes({'task.py':'', name:'x'}, schema_version=2)
        with self.assertRaises(PolicyError):
            job_bytes({'task.py':'', 'App/main.py':'', 'app/Main.py':''}, schema_version=2)

    def test_selected_multifile_sources_execute_only_in_container(self):
        r = self.probe()
        self.assertEqual(r['status'], 'HTTP_CHECKS_PASSED', r)
        self.assertEqual(r['security_verdict'], 'NOT_EVALUATED')
        self.assertIsNone(r['finding_status'])
        self.assertEqual(r['cleanup'], 'PASS')
        self.assertEqual(r['image_id'], IMAGE)
        self.assertEqual(r['target_image_id'], FAST_IMAGE)
        self.assertEqual(r['module'], 'app.main')
        self.assertEqual(r['source_file_count'], 3)
        self.assertTrue(all(row['passed'] for row in r['observations']))
        self.assertEqual(len(r['package_sha256']), 64)
        payload = parse_job(FakeAttachment.inputs[-1][1])
        self.assertEqual(payload['schema_version'], 2)
        self.assertEqual(set(payload['files']), {'task.py','app/__init__.py','app/main.py','app/routes.py'})
        self.assertIn("uvicorn.run('app.main:app'", payload['files']['task.py'])
        self.assertIn('from app.routes import router', payload['files']['app/main.py'])
        self.assertNotIn('README.txt', payload['files'])
        self.assertNotIn('pyproject.toml', payload['files'])
        self.assertNotIn('pip install', payload['files']['task.py'])
        for args,_ in self.fake.calls:
            self.assertNotIn('--publish', args)
            self.assertNotIn('--volume', args)
        receipt=json.loads((Path(r['record']).parent/'docker_receipt.json').read_text())
        self.assertEqual(receipt['binding']['package_sha256'],r['package_sha256'])

    def test_explicit_service_root_restricts_scope_and_import_name(self):
        backend = self.project / 'services' / 'first'
        backend.parent.mkdir()
        shutil.copytree(self.project / 'app', backend / 'app')
        (self.project / 'other.py').write_text('raise RuntimeError("do not load")')
        self.sid = self.snapshot()
        r = self.probe(entry='services/first/app/main.py', service='services/first')
        self.assertEqual(r['status'], 'HTTP_CHECKS_PASSED', r)
        packet=parse_job(FakeAttachment.inputs[-1][1])['files']
        self.assertEqual(set(packet), {'task.py','app/__init__.py','app/main.py','app/routes.py'})
        self.assertIn("uvicorn.run('app.main:app'", packet['task.py'])
        self.assertNotIn('other.py',packet)

    def test_execute_and_contract_required_before_docker(self):
        with self.assertRaises(PolicyError):
            self.probe(execute=False)
        with self.assertRaises(PolicyError):
            package_probe_snapshot(self.store,self.sid,'app/main.py',[],execute=True,
                                   broker_factory=self.factory)
        self.assertEqual(self.fake.calls,[])

    def test_path_traversal_and_out_of_service_rejected(self):
        for entry,service in (('../evil.py','.'), ('app\\main.py','.'),
                              ('app/main.py','other'), ('app/main.py','../../bad'),
                              ('app/missing.py','.'), ('app/main.txt','.')):
            with self.subTest(entry=entry,service=service),self.assertRaises(PolicyError):
                self.probe(entry=entry,service=service)
        self.assertEqual(self.fake.calls,[])

    def test_modified_snapshot_blocks_before_docker(self):
        member=self.store.root/'snapshots'/self.sid/'workspace'/'app'/'routes.py'
        member.write_text('print("CHANGED")',encoding='utf-8')
        with self.assertRaises(PolicyError): self.probe()
        self.assertEqual(self.fake.calls,[])

    def test_missing_package_initializer_blocks(self):
        (self.project/'app'/'__init__.py').unlink()
        self.sid=self.snapshot()
        with self.assertRaisesRegex(PolicyError,'__init__'):
            self.probe()
        self.assertEqual(self.fake.calls,[])

    def test_bounds_reject_service_with_too_many_files(self):
        for i in range(35):
            (self.project/'app'/f'm{i}.py').write_text('x=1\n',encoding='utf-8')
        self.sid=self.snapshot()
        with self.assertRaisesRegex(PolicyError,'1..31'):
            self.probe()
        self.assertEqual(self.fake.calls,[])

    def test_bounds_reject_large_source_module(self):
        (self.project/'app'/'routes.py').write_text('x = ' + repr('a'*100_000))
        self.sid=self.snapshot()
        with self.assertRaisesRegex(PolicyError,'96 KiB'):
            self.probe()
        self.assertEqual(self.fake.calls,[])

    def test_payload_total_bound_blocks_before_docker(self):
        for i in range(4):
            (self.project/'app'/f'large{i}.py').write_text('x=' + repr('z'*50000), encoding='utf-8')
        self.sid=self.snapshot()
        with self.assertRaisesRegex(PolicyError,'byte limit'):
            self.probe()
        self.assertEqual(self.fake.calls,[])

    def test_reserved_worker_entry_never_overwritten(self):
        (self.project/'task.py').write_text('print("USER TASK")', encoding='utf-8')
        self.sid=self.snapshot()
        with self.assertRaisesRegex(PolicyError,'reserved task.py'):
            self.probe()
        self.assertEqual(self.fake.calls,[])

    def test_missing_or_mislabelled_image_fails_closed(self):
        self.fake.missing_image=True
        r=self.probe()
        self.assertEqual(r['status'],'BLOCKED')
        self.assertEqual(r['security_verdict'],'NOT_EVALUATED')
        self.assertFalse(any(args[0]=='create' for args,_ in self.fake.calls))

    def test_failure_cleanup_and_unreachable_not_fixed(self):
        self.fake.status_override=403
        r=self.probe()
        self.assertEqual(r['status'],'HTTP_CHECKS_FAILED')
        self.assertEqual(r['security_verdict'],'NOT_EVALUATED')
        self.fake.cleanup_failure=True
        r=self.probe()
        self.assertEqual(r['status'],'BLOCKED')
        self.fake.cleanup_failure=False
        self.fake.verifier_problem='unreachable'
        r=self.probe()
        self.assertEqual(r['status'],'BLOCKED')
        self.assertNotIn('FIXED',json.dumps(r))

    def test_bad_receipt_or_target_image_blocks(self):
        self.fake.verifier_problem='bad-nonce'
        r=self.probe()
        self.assertEqual(r['status'],'BLOCKED')
        self.fake.verifier_problem=None
        self.fake.bad_runtime_image=True
        r=self.probe()
        self.assertEqual(r['status'],'BLOCKED')

    def test_cli_without_execute_keeps_scan_blocked(self):
        out=io.StringIO();err=io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=main(['--state',str(self.store.root),'repo','fastapi-package-probe',
                       self.sid,'--entry','app/main.py','--expect','/health=200'])
        self.assertEqual(code,2)
        self.assertIn('explicit --execute',err.getvalue())
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=main(['--state',str(self.store.root),'scan',str(self.project)])
        self.assertEqual(code,2)
        self.assertIn('BLOCKED',err.getvalue())

if __name__ == '__main__': unittest.main()
