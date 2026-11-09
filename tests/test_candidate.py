"""S5 tests. Only developer-owned constants execute locally, Docker is mocked."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
from securitylab.ai_contract import request, prompt, validate_proposal
from securitylab.candidate_policy import validate_candidate
from securitylab.candidate_verifier import verify_candidate, TASK, expected
from securitylab.fixture import FIXED, VULNERABLE
from securitylab.job_contract import parse_job
from securitylab.policy import PolicyError
from securitylab.storage import atomic_text, Store

ALTERNATIVE = FIXED.replace('    if record["owner"] != user:\n        return 403, None\n    return 200, record["value"]',
    '    if user == record["owner"]:\n        return 200, record["value"]\n    return 403, None')
BROKEN = FIXED.replace('return 404, None', 'return 200, None')
CRASH = FIXED.replace('record = RECORDS.get(record_id)', 'record = RECORDS[record_id]')

class TestBroker:
    def __init__(self, fault=None): self.fault=fault; self.payloads=[]
    def run(self, payload, directory, limits, *, binding):
        job=parse_job(payload); self.payloads.append(job)
        assert job['files']['task.py'] == TASK
        assert job['files']['service.py'] in (VULNERABLE,FIXED,ALTERNATIVE,BROKEN,CRASH)
        with tempfile.TemporaryDirectory() as td:
            for name, value in job['files'].items():
                Path(td,name).write_text(value, encoding='utf-8')
            p=subprocess.run([sys.executable,'-B','task.py'],cwd=td,capture_output=True,text=True,timeout=5)
        identity=uuid.uuid4().hex
        r=dict(id=identity, binding=binding, image_id='sha256:'+'a'*64,
               payload_sha256=hashlib.sha256(payload).hexdigest(), cleanup='PASS',
               status='COMPLETED' if p.returncode==0 else 'NONZERO_EXIT',
               execution=dict(returncode=p.returncode, stdout=p.stdout, stderr=p.stderr,
                              timed_out=False, truncated=False, cancelled=False),
               container_state=dict(Running=False, ExitCode=p.returncode, OOMKilled=False, Error=''))
        if self.fault:self.fault(r)
        atomic_text(directory/(identity+'.json'), json.dumps(r))
        return r

class CandidateTests(unittest.TestCase):
    def test_alternative_admitted_but_old_gate_rejects(self):
        value={'file':'service.py','content':ALTERNATIVE}
        validate_proposal('blue',value,candidate=True)
        with self.assertRaises(PolicyError):validate_proposal('blue',value)
    def test_wrong_code_is_admitted_for_behavioral_testing(self):
        validate_candidate(VULNERABLE);validate_candidate(BROKEN)
    def test_restricted_language_denies_side_effects(self):
        for extra in ['import os','print("PASS")','open("task.py", "w")',
                      'record["owner"] = user','RECORDS = {}','global RECORDS',
                      'while True: pass','return __import__("os")',
                      'return record.__class__','return RECORDS.get','read_record(user, record_id)',
                      'return [x for x in RECORDS]', 'raise SystemExit(0)']:
            source=FIXED.replace('    return 200, record["value"]','    '+extra)
            with self.subTest(extra=extra),self.assertRaises(PolicyError):validate_candidate(source)
    def test_module_and_signature_changes_denied(self):
        for source in [FIXED+'\nprint("PASS")', FIXED.replace('alice','mallory'),
                       FIXED.replace('def read_record', '@print\ndef read_record'),
                       FIXED.replace('user, record_id','user, record_id=None')]:
            with self.assertRaises(PolicyError):validate_candidate(source)
    def test_request_mode_is_bound(self):
        finding=dict(file='service.py',description='access',user='attacker',record_id='one')
        req=request('blue',finding,candidate=True)
        self.assertNotIn('actual-candidate-v1',prompt(req))
        self.assertEqual(req['verification'],'actual-candidate-v1')
        with self.assertRaises(PolicyError):prompt(dict(req,verification='anything'))
    def check(self, source, fault=None):
        with tempfile.TemporaryDirectory() as td:
            broker=TestBroker(fault)
            result=verify_candidate(source,Path(td),broker_factory=lambda _:broker)
            saved=json.loads(Path(result['record']).read_text(encoding='utf-8'))
            self.assertEqual(saved,result)
            if result['status']=='PASS':
                self.assertEqual(Path(result['record']).with_name('candidate.txt').read_bytes(),source.encode())
            return result,broker
    def test_actual_alternative_bytes_and_three_receipts(self):
        r,b=self.check(ALTERNATIVE)
        self.assertEqual(r['status'],'PASS',r)
        self.assertEqual(r['finding_status'],'FIXED')
        self.assertEqual(len({p['receipt_id'] for p in r['proofs']}),3)
        self.assertEqual(b.payloads[1]['files']['service.py'],ALTERNATIVE)
        self.assertEqual(b.payloads[2]['files']['service.py'],ALTERNATIVE)
        self.assertEqual(r['proofs'][1]['observed'],expected(True))
    def test_unchanged_and_regression_fail(self):
        for source in [VULNERABLE,BROKEN]:
            r,_=self.check(source)
            self.assertEqual(r['status'],'NEEDS_REVIEW');self.assertIsNone(r['finding_status'])
    def test_crash_not_fix(self):
        r,_=self.check(CRASH)
        self.assertEqual(r['status'],'BLOCKED');self.assertIsNone(r['finding_status'])
    def test_transport_and_binding_failures(self):
        faults=[lambda r:r.update(cleanup='FAIL'),lambda r:r.update(payload_sha256='0'*64),
                lambda r:r.update(binding={}),lambda r:r.update(image_id='latest'),
                lambda r:r['execution'].update(timed_out=True),
                lambda r:r['execution'].update(truncated=True),
                lambda r:r['execution'].update(cancelled=True),
                lambda r:r['container_state'].update(OOMKilled=True),
                lambda r:r['container_state'].update(ExitCode=1),
                lambda r:r['execution'].update(stdout='{"status":"FIXED"}'),
                lambda r:r['execution'].update(stdout=json.dumps([[True,None]]*15))]
        for fault in faults:
            r,_=self.check(FIXED,fault)
            self.assertEqual(r['status'],'BLOCKED',r);self.assertIsNone(r['finding_status'])
    def test_policy_failure_never_constructs_broker(self):
        with tempfile.TemporaryDirectory() as td:
            def forbidden(_):self.fail('Broker must not be created')
            r=verify_candidate(FIXED+'\nimport os',Path(td),broker_factory=forbidden)
            self.assertEqual(r['status'],'BLOCKED')
    def test_ai_workflow_candidate_mode(self):
        from test_ai import Adapter, envelope
        from securitylab.ai_workflow import run_ai
        class CandidateAdapter(Adapter):
            def ask(self,req):
                v,c=super().ask(req)
                if req['role']=='blue':
                    self_test.assertEqual(req['verification'],'actual-candidate-v1')
                    v['content']=ALTERNATIVE;c['response']=envelope(req,v)
                return v,c
        self_test=self
        with tempfile.TemporaryDirectory() as td:
            s=Store(Path(td));Adapter.bad=False
            try:
                r=run_ai(s,adapter_factory=CandidateAdapter,candidate=True,
                         verifier=lambda source,root:verify_candidate(source,root,broker_factory=lambda _:TestBroker()))
                self.assertEqual(r['status'],'PASS',r)
                self.assertEqual(r['mode'],'hermes-actual-candidate-fixture')
                self.assertEqual(s.runs(),[])
                self.assertTrue(Path(r['verification_record']).exists())
            finally:s.close()

class CandidateIntegrationTests(unittest.TestCase):
    def test_worker_and_envelope_admit_noncanonical_proposal(self):
        from test_ai import Agent, envelope, RED
        from securitylab.hermes_worker import invoke
        from securitylab.hermes_adapter import validate_envelope
        class ReplyAgent(Agent):
            tool_list=[];messages=[]
            reply=json.dumps({'file':'service.py','content':ALTERNATIVE})
        req=request('blue',RED,candidate=True)
        proposal=invoke(req,ReplyAgent)
        self.assertEqual(validate_envelope(req,envelope(req,proposal))['content'],ALTERNATIVE)
        with self.assertRaises(PolicyError):
            validate_envelope(request('blue',RED),envelope(req,proposal))

    def test_corrective_attempt_preserves_candidate_mode(self):
        from test_ai import BlueAttemptTransport, RED
        from securitylab.hermes_adapter import HermesAdapter
        class Transport(BlueAttemptTransport):
            requests=[]
            def __call__(self,argv,cwd,limits,**kwargs):
                if 'input_data' in kwargs and kwargs['input_data']:
                    self.requests.append(json.loads(kwargs['input_data']))
                return super().__call__(argv,cwd,limits,**kwargs)
        with tempfile.TemporaryDirectory() as td:
            transport=Transport()
            HermesAdapter(Path(td),Path(td)/'calls',transport).ask(request('blue',RED,candidate=True))
            self.assertEqual(len(transport.requests),2)
            self.assertTrue(all(r['verification']=='actual-candidate-v1' for r in transport.requests))

    def test_saved_summary_cli_without_model(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch
        from securitylab.cli import main
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'saved.json'
            path.write_text(json.dumps({'blue':{'file':'service.py','content':ALTERNATIVE}}),encoding='utf-8')
            def verify(source, root, **kwargs):
                return verify_candidate(source,root,broker_factory=lambda _:TestBroker(),**kwargs)
            with patch('securitylab.candidate_verifier.verify_candidate',side_effect=verify),redirect_stdout(StringIO()) as output:
                code=main(['--state',str(Path(td)/'state'),'candidate-check','--summary',str(path)])
            self.assertEqual(code,0,output.getvalue())
            self.assertEqual(json.loads(output.getvalue())['status'],'PASS')

    def test_old_receipt_tamper_prevents_success(self):
        class TamperingBroker(TestBroker):
            def run(self,payload,directory,limits,**kwargs):
                result=super().run(payload,directory,limits,**kwargs)
                if kwargs['binding']['kind']=='recheck':
                    for path in directory.glob('*.json'):
                        data=json.loads(path.read_text())
                        if data['binding']['kind']=='baseline':
                            data['execution']['stdout']='[]'
                            atomic_text(path,json.dumps(data))
                return result
        with tempfile.TemporaryDirectory() as td:
            r=verify_candidate(ALTERNATIVE,Path(td),broker_factory=lambda _:TamperingBroker())
            self.assertEqual(r['status'],'BLOCKED');self.assertIsNone(r['finding_status'])
