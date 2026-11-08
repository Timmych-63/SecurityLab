"""Contract integration with a fake Docker transport, NOT a live Docker test."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from securitylab.docker_fixture import DockerFixtureRunner, recipe, KINDS
from securitylab.fixture import FIXED, VULNERABLE, REGRESSION
from securitylab.orchestrator import Orchestrator
from securitylab.policy import Limits, PolicyError
from securitylab.runner import FixtureRunner
from securitylab.storage import Store, atomic_text
from securitylab.validator import confirmed

MODE = 'scripted-demo-docker-no-ai'

class FixtureBroker:
    """Executes only reviewed constants locally; fabricates transport metadata."""
    def __init__(self):
        self.calls=[];self.fault=None;self.stop_hook=None
    def run(self, payload, output, limits, *, binding=None, stop=None):
        kind=binding['kind'];self.calls.append(kind)
        assert payload == recipe(kind)[2], 'Only known fixture recipes may execute in this test'
        rid=uuid.uuid4().hex
        record={'id':rid,'image_id':'sha256:'+'a'*64,'binding':dict(binding),
                'payload_sha256':hashlib.sha256(payload).hexdigest(),'cleanup':'PASS'}
        if self.stop_hook:self.stop_hook()
        if stop and stop():
            record['status']='CANCELLED'
        else:
            with tempfile.TemporaryDirectory() as td:
                repo=Path(td)
                atomic_text(repo/'service.py', VULNERABLE if kind=='baseline' else FIXED)
                atomic_text(repo/'test_regression.py',REGRESSION)
                runner=FixtureRunner(limits)
                if kind in ('baseline','mandatory','recheck'):
                    e=runner.suite(repo,binding['revision'],kind!='baseline')
                elif kind=='build':e=runner.build(repo,binding['revision'])
                else:e=runner.regression(repo,binding['revision'])
                result=e['result'];record['execution']=result
                record['status']='COMPLETED' if result['returncode']==0 else 'NONZERO_EXIT'
                record['container_state']={'Running':False,'ExitCode':result['returncode'],'OOMKilled':False,'Error':''}
        if self.fault:self.fault(record)
        atomic_text(output/(rid+'.json'),json.dumps(record,indent=2))
        return record

class DockerWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=Store(self.root/'state');self.broker=FixtureBroker()
        self.engine=Orchestrator(self.store,docker_broker_factory=lambda:self.broker)
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def complete(self):
        rid=self.store.create(MODE);row=self.engine.run(rid)
        self.assertEqual(row['status'],'DONE',row)
        self.assertEqual(self.store.finding(rid)['status'],'FIXED')
        return rid
    def receipt(self,rid,kind):
        e=self.store.evidence(rid)[kind]
        return self.store.root/'runs'/rid/'receipts'/(e['receipt_id']+'.json')
    def auditor(self,rid):
        return DockerFixtureRunner(rid,self.store.root/'runs'/rid/'receipts',broker=self.broker)
    def test_full_workflow_uses_five_distinct_bound_checks(self):
        rid=self.complete();e=self.store.evidence(rid)
        self.assertEqual(self.broker.calls,['baseline','regression','build','mandatory','recheck'])
        self.assertEqual(e['verdict']['executor'],'docker')
        self.assertEqual(self.store.get(rid)['mode'],MODE)
        self.assertEqual(len({e[k]['receipt_id'] for k in KINDS}),5)
        self.assertEqual(self.auditor(rid).audit(e),[])
    def test_missing_receipt_rejected(self):
        rid=self.complete();self.receipt(rid,'recheck').unlink()
        self.assertTrue(self.auditor(rid).audit(self.store.evidence(rid)))
    def test_edited_receipt_rejected(self):
        rid=self.complete();p=self.receipt(rid,'build')
        body=json.loads(p.read_text(encoding='utf-8'));body['cleanup']='FAIL'
        atomic_text(p,json.dumps(body))
        self.assertTrue(self.auditor(rid).audit(self.store.evidence(rid)))
    def test_wrong_run_rejected(self):
        rid=self.complete()
        other=DockerFixtureRunner(uuid.uuid4().hex,self.store.root/'runs'/rid/'receipts',broker=self.broker)
        self.assertTrue(other.audit(self.store.evidence(rid)))
    def test_copied_check_rejected(self):
        rid=self.complete();e=self.store.evidence(rid)
        e['recheck']=copy.deepcopy(e['mandatory'])
        self.assertTrue(self.auditor(rid).audit(e))
    def test_stdout_claim_without_receipts_rejected(self):
        rid=self.store.create(MODE)
        self.assertTrue(self.auditor(rid).audit({'status':'FIXED','stdout':'all tests passed'}))
    def test_changed_parsed_checks_rejected(self):
        rid=self.complete();e=self.store.evidence(rid)
        e['recheck']['checks']['owner_read']=False
        self.assertTrue(self.auditor(rid).audit(e))
    def test_wrong_payload_before_confirmation_blocked(self):
        self.broker.fault=lambda r:r.update(payload_sha256='0'*64)
        rid=self.store.create(MODE);row=self.engine.run(rid)
        self.assertEqual(row['status'],'BLOCKED')
        self.assertEqual(self.store.finding(rid)['status'],'HYPOTHESIS')
    def test_failed_cleanup_cannot_confirm(self):
        self.broker.fault=lambda r:r.update(cleanup='FAIL')
        rid=self.store.create(MODE);self.engine.run(rid)
        self.assertEqual(self.store.get(rid)['status'],'BLOCKED')
        self.assertEqual(self.broker.calls,['baseline'])
    def test_no_docker_does_not_fall_back_to_host(self):
        def unavailable():raise PolicyError('Docker unavailable')
        rid=self.store.create(MODE)
        row=Orchestrator(self.store,docker_broker_factory=unavailable).run(rid)
        self.assertEqual(row['status'],'BLOCKED')
        self.assertEqual(row['stage'],'QUEUED')
        self.assertFalse(self.engine.repo(rid).exists())
    def test_mode_persists_and_resume_runs_only_remaining_checks(self):
        class Crash(BaseException):pass
        rid=self.store.create(MODE)
        def crash(stage):
            if stage=='CONFIRMED':raise Crash()
        with self.assertRaises(Crash):self.engine.run(rid,after_stage=crash)
        self.store.close();self.store=Store(self.root/'state')
        other=Orchestrator(self.store,docker_broker_factory=lambda:self.broker)
        other.run(rid)
        self.assertEqual(self.store.finding(rid)['status'],'FIXED')
        self.assertEqual(self.broker.calls.count('baseline'),1)
    def test_receipt_tamper_before_final_validation_needs_review(self):
        rid=self.store.create(MODE)
        def tamper(stage):
            if stage=='VERIFIED':self.receipt(rid,'mandatory').unlink()
        self.engine.run(rid,after_stage=tamper)
        self.assertEqual(self.store.finding(rid)['status'],'NEEDS_REVIEW')
    def test_keyboard_cancel_is_recorded_as_stopped(self):
        rid=self.store.create(MODE)
        self.broker.fault=lambda r:r.update(status='CANCELLED')
        with self.assertRaises(KeyboardInterrupt):self.engine.run(rid)
        self.assertEqual(self.store.get(rid)['status'],'STOPPED')
    def test_stop_reaches_broker_and_task_stops(self):
        rid=self.store.create(MODE);self.broker.stop_hook=lambda:self.store.stop(rid)
        row=self.engine.run(rid)
        self.assertEqual(row['status'],'STOPPED')
        self.assertEqual(self.broker.calls,['baseline'])
    def test_local_job_after_docker_job_does_not_reuse_docker_runner(self):
        self.complete();self.broker.calls=[]
        rid=self.store.create();self.engine.run(rid)
        self.assertEqual(self.store.finding(rid)['status'],'FIXED')
        self.assertEqual(self.broker.calls,[])
    def test_unrecognized_mode_rejected(self):
        with self.assertRaises(PolicyError):self.store.create('agent-chosen-backend')
    def test_untrusted_source_never_sent_to_broker(self):
        rid=self.store.create(MODE);repo=self.engine.repo(rid);repo.mkdir(parents=True)
        atomic_text(repo/'service.py','print("FIXED")')
        with self.assertRaises(PolicyError):self.auditor(rid).suite(repo,'a'*40,False)
        self.assertEqual(self.broker.calls,[])
    def test_malformed_check_map_is_not_confirmed(self):
        rid=self.complete();e=self.store.evidence(rid)['baseline'];e['checks']=[]
        self.assertFalse(confirmed(e))
