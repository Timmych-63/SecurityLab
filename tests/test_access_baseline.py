"""S7.1 access baseline tests: Docker simulated except local verifier socket test."""
from __future__ import annotations

import base64
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

from securitylab.access_baseline import (_classify, access_baseline_snapshot,
                                         read_external_policy, validate_policy)
from securitylab.cli import main
from securitylab.http_runner import FastAPIHTTPDockerBroker, VERIFIER_SCRIPT
from securitylab.job_contract import parse_job
from securitylab.policy import PolicyError
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot
from securitylab.storage import Store
from test_fastapi_probe import FakeFastAPIDocker, FAST_IMAGE
from test_http_probe import FakeAttachment, IMAGE, response

HERE = Path(__file__).resolve().parents[1]
POLICY = HERE / 'examples/security_policies/record_ownership.json'


class FakeAccessDocker(FakeFastAPIDocker):
    def __init__(self):
        super().__init__()
        self.vulnerable = True
        self.empty_control = False
        self.unmatched_body = False
        self.truncated_body = False
        self.bad_actor = False
        self.bad_digest = False
        self.unauthorized_status = None

    def __call__(self, argv, cwd, limits, **kwargs):
        args = argv[3:] if argv[1:2] == ['--host'] else argv[1:]
        if args[:2] == ['start', '--attach']:
            self.calls.append((args, kwargs))
            verifier = self.containers[args[2]]
            encoded = verifier[verifier.index('--env') + 1].split('=', 1)[1]
            contract = json.loads(base64.b64decode(encoded).decode())
            rows = []
            for c in contract['checks']:
                control = ((c['actor'] == 'alice' and c['path'] == '/records/one') or
                           (c['actor'] == 'bob' and c['path'] == '/records/two'))
                code = (401 if c['actor'] is None else 404 if c['path'].endswith('/missing')
                        else 200 if control or self.vulnerable else 403)
                if not control and self.unauthorized_status is not None:
                    code = self.unauthorized_status
                key=c['path'].rsplit('/',1)[1]
                record={'id':key, 'owner':'alice' if key=='one' else 'bob',
                        'value':'synthetic-A' if key=='one' else 'synthetic-B'}
                body=(json.dumps(record,separators=(',',':')).encode() if code==200 else json.dumps({'detail':{401:'Unauthorized',403:'Forbidden',404:'Not Found'}[code]},separators=(',',':')).encode())
                if self.empty_control and control:
                    body = b''
                if self.unmatched_body and not control:
                    body = b'different-data'
                if self.truncated_body and not control:
                    body = b'z' * 4097
                row = {'path': c['path'], 'actor': c['actor'],
                       'expected_status': c['expected_status'],
                       'actual_status': code, 'passed': code == c['expected_status'],
                       'error': None,
                       'body_sha256': hashlib.sha256(body).hexdigest(),
                       'body_bytes': len(body), 'body_truncated':len(body) > 4096}
                rows.append(row)
            if self.bad_actor:
                rows[0]['actor'] = 'attacker'
            if self.bad_digest:
                rows[0]['body_sha256'] = 'invalid'
            self.results = {'schema_version': 1, 'nonce': contract['nonce'],
                            'observations':rows}
            return response(json.dumps(self.results),
                            code=0 if all(x['passed'] for x in rows) else 1)
        return super().__call__(argv, cwd, limits, **kwargs)


class AccessBaselineTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.project = self.root / 'target'
        shutil.copytree(HERE / 'examples/s7_repos/authz_vulnerable', self.project)
        self.policy_file = self.root / 'test_policy.json'
        shutil.copy2(POLICY, self.policy_file)
        self.store = Store(self.root / 'state')
        self.addCleanup(self.store.close)
        self.sid = self.snapshot()
        self.fake = FakeAccessDocker()

    def snapshot(self):
        pid = add_project(self.store, self.project, 'test-target')['id']
        return create_snapshot(self.store, pid)['snapshot_id']

    def factory(self, cwd):
        return FastAPIHTTPDockerBroker(cwd, executor=self.fake, attachment_cls=FakeAttachment)

    def probe(self, **options):
        return access_baseline_snapshot(self.store, self.sid, 'app/main.py',
                                        self.policy_file, execute=True,
                                        broker_factory=self.factory, **options)

    def test_vulnerable_baseline_reproduces_body_of_owner_and_never_fixed(self):
        report = self.probe()
        self.assertEqual(report['status'], 'ACCESS_POLICY_VIOLATION_REPRODUCED', report)
        self.assertEqual(report['security_verdict'], 'POLICY_VIOLATION_OBSERVED')
        self.assertEqual(report['finding_status'], 'REPRODUCED')
        self.assertEqual(report['cleanup'], 'PASS')
        self.assertEqual(report['image_id'], IMAGE)
        self.assertEqual(report['target_image_id'], FAST_IMAGE)
        self.assertEqual([o['result'] for o in report['outcomes']],
                        ['UNAUTHORIZED_BODY_MATCHES_CONTROL'] * 2)
        self.assertNotIn('FIXED',json.dumps(report))
        payload = parse_job(FakeAttachment.inputs[-1][1])
        self.assertEqual(payload['schema_version'], 2)
        self.assertEqual(set(payload['files']), {'task.py','app/__init__.py','app/main.py'})
        self.assertIn('uvicorn.run(', payload['files']['task.py'])
        self.assertNotIn('test_policy.json', payload['files'])
        receipt = json.loads((Path(report['record']).parent / 'docker_receipt.json').read_text())
        self.assertEqual(receipt['binding']['policy_sha256'],report['policy_sha256'])
        self.assertEqual(receipt['binding']['checks_sha256'],report['checks_sha256'])
        self.assertFalse(any('--publish' in args or '--volume' in args for args,_ in self.fake.calls))

    def test_corrected_behavior_does_not_claim_security_proven(self):
        self.fake.vulnerable = False
        report = self.probe()
        self.assertEqual(report['status'], 'ACCESS_POLICY_MATCHED',report)
        self.assertEqual(report['security_verdict'], 'NOT_PROVEN_SAFE')
        self.assertIsNone(report['finding_status'])

    def test_control_failure_needs_review(self):
        self.fake.empty_control = True
        report = self.probe()
        self.assertEqual(report['status'], 'NEEDS_REVIEW',report)
        self.assertIsNone(report['finding_status'])

    def test_wrong_operator_anchored_body_hash_not_reproduced(self):
        policy=json.loads(self.policy_file.read_text())
        policy['checks'][0]['expected_body_sha256']='0'*64
        self.policy_file.write_text(json.dumps(policy))
        report=self.probe()
        self.assertEqual(report['status'],'NEEDS_REVIEW')
        self.assertIsNone(report['finding_status'])

    def test_unexpected_success_without_matching_body_not_confirmed(self):
        self.fake.unmatched_body = True
        report = self.probe()
        self.assertEqual(report['status'], 'NEEDS_REVIEW',report)
        self.assertIsNone(report['finding_status'])

    def test_unauthorized_error_does_not_become_reproduced(self):
        self.fake.unauthorized_status = 404
        report = self.probe()
        self.assertEqual(report['status'], 'NEEDS_REVIEW')
        self.assertIsNone(report['finding_status'])

    def test_truncation_blocks_body_claim(self):
        self.fake.truncated_body = True
        report = self.probe()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertIn('4096', report['error'])

    def test_broker_rejects_forged_actor_or_body_digest(self):
        for flag in ('bad_actor','bad_digest'):
            self.fake = FakeAccessDocker()
            setattr(self.fake, flag, True)
            report = self.probe()
            self.assertEqual(report['status'], 'BLOCKED',report)
            self.assertIsNone(report['finding_status'])

    def test_cleanup_and_runtime_failure_never_confirm(self):
        self.fake.cleanup_failure = True
        report = self.probe()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertIsNone(report['finding_status'])
        self.fake = FakeAccessDocker()
        self.fake.missing_image = True
        report = self.probe()
        self.assertEqual(report['status'], 'BLOCKED')

    def test_snapshot_modified_blocks_before_docker(self):
        file = self.store.root / 'snapshots' / self.sid / 'workspace' / 'app' / 'main.py'
        file.write_text('print("tampered")',encoding='utf-8')
        with self.assertRaises(PolicyError):
            self.probe()
        self.assertEqual(self.fake.calls,[])

    def test_external_policy_cannot_be_inside_target_or_state(self):
        (self.project / 'check.json').write_bytes(self.policy_file.read_bytes())
        for path in (self.project / 'check.json', self.store.root / 'check.json'):
            if path.parent == self.store.root:
                path.write_bytes(self.policy_file.read_bytes())
            with self.subTest(path=path), self.assertRaisesRegex(PolicyError,'outside'):
                read_external_policy(self.store,self.sid,path)
        self.assertEqual(self.fake.calls,[])

    def test_invalid_policy_schema_and_duplicate_keys(self):
        good = json.loads(self.policy_file.read_text())
        for changed in (
            dict(good, schema_version=True),
            dict(good, checks=good['checks'][:2]),
            dict(good, checks=[{**good['checks'][0], 'actor':'bad\r\nInjected'}] + good['checks'][1:]),
            dict(good, checks=[{**good['checks'][2], 'compare_body_to':'unknown'}] + good['checks'][:2] + good['checks'][3:]),
            dict(good, checks=[{**good['checks'][0], 'expected_status':201}] + good['checks'][1:]),
            dict(good, checks=[{**good['checks'][2], 'path':'//evil'}] + good['checks'][:2] + good['checks'][3:]),
        ):
            with self.subTest(changed=changed), self.assertRaises(PolicyError):
                validate_policy(changed)
        self.policy_file.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(PolicyError, 'Duplicate field'):
            read_external_policy(self.store,self.sid,self.policy_file)
        self.assertEqual(self.fake.calls,[])

    def test_symlink_and_oversize_policy_refused(self):
        self.policy_file.write_bytes(b'x' * 13000)
        with self.assertRaises(PolicyError):
            self.probe()
        self.policy_file.unlink()
        try:
            self.policy_file.symlink_to(POLICY)
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation restricted')
        with self.assertRaises(PolicyError):
            self.probe()
        self.assertEqual(self.fake.calls,[])

    def test_explicit_execute_and_policy_before_docker(self):
        with self.assertRaisesRegex(PolicyError,'explicit --execute'):
            access_baseline_snapshot(self.store,self.sid,'app/main.py',self.policy_file,
                                     broker_factory=self.factory)
        with self.assertRaises(PolicyError):
            access_baseline_snapshot(self.store,self.sid,'../bad.py',self.policy_file,
                                     execute=True,broker_factory=self.factory)
        self.assertEqual(self.fake.calls,[])

    def test_cli_requires_execute_and_scan_remains_blocked(self):
        out=io.StringIO();err=io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=main(['--state',str(self.store.root), 'repo', 'access-baseline',self.sid,
                       '--entry','app/main.py','--policy',str(self.policy_file)])
        self.assertEqual(code,2)
        self.assertIn('--execute',err.getvalue())
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=main(['--state',str(self.store.root), 'scan',str(self.project)])
        self.assertEqual(code,2)
        self.assertIn('BLOCKED',err.getvalue())

    def test_cli_with_fake_broker_via_direct_function(self):
        report=self.probe()
        self.assertTrue(Path(report['record']).is_file())
        doc=json.loads(Path(report['record']).read_text())
        self.assertEqual(doc,report)


class TrustedVerifierActorTests(unittest.TestCase):
    def test_fixed_verifier_uses_synthetic_actor_header_and_body_digest(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                actor=self.headers.get('X-Test-User')
                data=('hello-'+actor).encode() if actor else b'not-authenticated'
                self.send_response(200 if actor=='alice' else 401 if actor is None else 403)
                self.send_header('Content-Length',str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self,*_): pass
        try:
            server=HTTPServer(('127.0.0.1',0),Handler)
        except OSError:
            self.skipTest('Local socket unavailable')
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            port=server.server_address[1]
            script=VERIFIER_SCRIPT.replace("HTTPConnection('target',8000",f"HTTPConnection('127.0.0.1',{port}")
            checks=[{'path':'/records/one','actor':'alice','expected_status':200},
                    {'path':'/records/one','actor':'bob','expected_status':403},
                    {'path':'/records/one','actor':None,'expected_status':401}]
            environment={**os.environ,
                'SL_HTTP_CONTRACT':base64.b64encode(json.dumps({'checks':checks,'nonce':'test'}).encode()).decode()}
            result=subprocess.run([sys.executable,'-I','-B','-c',script],env=environment,
                                  cwd=tempfile.gettempdir(),capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            obs=json.loads(result.stdout)['observations']
            self.assertEqual([r['actor'] for r in obs],['alice','bob',None])
            self.assertEqual(obs[0]['body_sha256'],hashlib.sha256(b'hello-alice').hexdigest())
            self.assertEqual(obs[1]['body_sha256'],hashlib.sha256(b'hello-bob').hexdigest())
            self.assertEqual(obs[2]['body_sha256'],hashlib.sha256(b'not-authenticated').hexdigest())
            self.assertTrue(all(row['passed'] for row in obs))
        finally:
            server.shutdown();server.server_close();thread.join(timeout=5)


if __name__=='__main__':
    unittest.main()
