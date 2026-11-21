"""Cancellation contracts: mocked model/Docker, real core workflow and isolated Git."""
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import test_access_ai as fixture
import test_dashboard as dashboard_fixture
from test_http_probe import FakeHTTPDocker, FakeAttachment
from test_container_runner import response
from securitylab.access_ai import run_access_ai
from securitylab.http_runner import HTTPDockerBroker
from securitylab.job_contract import job_bytes
from securitylab.policy import PolicyError
from securitylab.run_control import RunControl

class StopAwareHermes(fixture.FakeHermes):
    def ask(self,req,stop=None): return super().ask(req)

class CancelCoreTests(unittest.TestCase):
    setUp=fixture.AccessAIFixture.setUp
    def run_controlled(self,stop,progress=None,adapter=StopAwareHermes,observer=None):
        def observe(*args,stop=None,**kwargs):
            result=self.observer(*args,**kwargs)
            receipt=args[0]/'docker_receipt.json'
            data=json.loads(receipt.read_text());data['cleanup']='PASS'
            receipt.write_text(json.dumps(data))
            result['receipt_sha256']=hashlib.sha256(receipt.read_bytes()).hexdigest()
            return result
        return run_access_ai(self.store,self.sid,'app/main.py',self.policy,execute=True,
            adapter_factory=adapter,observer=observer or observe,stop=stop,progress=progress)

    def test_cancel_before_first_call_creates_no_container_or_commit(self):
        result=self.run_controlled(lambda:True)
        self.assertEqual(result['status'],'STOPPED')
        self.assertEqual(result['cleanup'],'PASS')
        self.assertNotIn('git',result)
        self.assertEqual(result['stages'],{})

    def test_cancel_after_baseline_preserves_evidence_and_stops_blue(self):
        event=threading.Event();events=[]
        def progress(stage,state,text):
            events.append((stage,state))
            if stage=='baseline' and state=='done':event.set()
        result=self.run_controlled(event.is_set,progress)
        self.assertEqual(result['status'],'STOPPED')
        self.assertIn('baseline',result['stages'])
        self.assertNotIn('candidates',result)
        self.assertEqual([r['role'] for r in result['ai_calls']],['red'])
        self.assertIn(('red','wait_model'),events)

    def test_ai_cancel_requires_cleanup_pass(self):
        for cleanup in ('PASS','FAIL','NOT_TESTED'):
            with self.subTest(cleanup=cleanup):
                event=threading.Event()
                class CancelHermes(fixture.FakeHermes):
                    def ask(inner,req,stop=None):
                        (inner.output/('d'*32+'.json')).write_text(json.dumps({'status':'CANCELLED','cleanup':cleanup}))
                        event.set();raise PolicyError('AI cancelled')
                result=self.run_controlled(event.is_set,adapter=CancelHermes)
                self.assertEqual(result['status'],'STOPPED' if cleanup=='PASS' else 'BLOCKED')
                self.assertIsNone(result['finding_status'])

    def test_verifier_cancel_requires_cleanup_and_never_commits(self):
        for cleanup in ('PASS','FAIL'):
            with self.subTest(cleanup=cleanup):
                event=threading.Event()
                def observer(folder,*args,stop=None,**kwargs):
                    folder.mkdir(parents=True,exist_ok=True)
                    (folder/'docker_receipt.json').write_text(json.dumps({'cleanup':cleanup,'status':'BLOCKED'}))
                    event.set();raise PolicyError('HTTP verifier cancelled')
                result=self.run_controlled(event.is_set,observer=observer)
                self.assertEqual(result['status'],'STOPPED' if cleanup=='PASS' else 'BLOCKED')
                self.assertNotIn('git',result)

    def test_two_candidates_have_separate_diffs_relative_to_original(self):
        original=(self.src/'app/main.py').read_text()
        with patch.object(StopAwareHermes,'blue_text',[original+'\n# unsuccessful\n',fixture.FIX.rstrip('\n')]):
            result=self.run_controlled(lambda:False)
        self.assertEqual(result['status'],'PASS',result)
        folder=Path(result['record']).parent
        first=(folder/'candidate_1.patch').read_text()
        second=(folder/'candidate_2.patch').read_text()
        self.assertIn('+# unsuccessful',first)
        self.assertNotIn('-# unsuccessful',second)
        self.assertIn('No newline at end of file',second)
        self.assertIn("+    if x_test_user != record['owner']:",second)

class CancelBrokerTests(unittest.TestCase):
    def test_http_executor_receives_stop_and_all_owned_resources_are_cleaned(self):
        event=threading.Event();fake=FakeHTTPDocker();seen=[]
        def executor(argv,cwd,limits,**kwargs):
            if 'start' in argv and '--attach' in argv:
                seen.append(kwargs['stop']);event.set()
                self.assertTrue(kwargs['stop']())
                return response(code=-9,cancelled=True)
            return fake(argv,cwd,limits,**kwargs)
        with tempfile.TemporaryDirectory() as temp:
            broker=HTTPDockerBroker(Path(temp),executor=executor,attachment_cls=FakeAttachment)
            result=broker.run(job_bytes({'task.py':'print(1)'}),[{'path':'/','expected_status':200}],Path(temp),binding={},stop=event.is_set)
        self.assertEqual(result['cleanup'],'PASS');self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(len(seen),1)
        self.assertEqual(sum(args[:2]==['rm','--force'] for args,_ in fake.calls),2)
        self.assertTrue(any(args[:2]==['network','rm'] for args,_ in fake.calls))

class ControlTests(unittest.TestCase):
    def test_events_bounded_and_cancel_is_not_terminal(self):
        with tempfile.TemporaryDirectory() as temp:
            c=RunControl(Path(temp)/'live.json')
            for i in range(205):c.emit('red','wait_model',str(i))
            c.cancel()
            saved=json.loads(c.path.read_text())
            self.assertEqual(len(saved['events']),200)
            self.assertTrue(saved['cancelRequested'])
            self.assertEqual(saved['stages'][-1]['state'],'running')
            c.finish('STOPPED')
            self.assertEqual(json.loads(c.path.read_text())['stages'][-1]['detail'],'Результат: STOPPED')

class CancelAPITests(unittest.TestCase):
    setUp=dashboard_fixture.DashboardTests.setUp
    def test_cancel_returns_request_then_worker_finishes(self):
        import time
        entered=threading.Event();release=threading.Event()
        def runner(*args,stop,progress,**kwargs):
            entered.set();release.wait(3)
            self.assertTrue(stop())
            return {'status':'STOPPED'}
        self.app.runner=runner
        cfg=self.app.profiles.get('default')
        self.app.grants[json.dumps(self.inp,sort_keys=True)]=(time.monotonic(),cfg.sha256)
        rid=self.app.launch(self.inp)['runId']
        try:
            self.assertTrue(entered.wait(2))
            reply=self.app.dispatch('POST',f'/api/runs/{rid}/cancel')
            self.assertEqual(reply['state'],'CANCEL_REQUESTED')
            view=self.app.run(rid)
            self.assertEqual(view['exec'],'running')
            self.assertTrue(view['cancelRequested'])
        finally: release.set()
        for _ in range(100):
            if self.app.active is None:break
            time.sleep(.01)
        self.assertEqual(self.app.run(rid)['exec'],'cancelled')
        with self.assertRaises(PolicyError):self.app.cancel(rid)

class HermesCancellationTests(unittest.TestCase):
    def test_real_adapter_passes_stop_and_saves_cleanup_receipt(self):
        from test_ai import DockerTransport
        from securitylab.hermes_adapter import HermesAdapter
        from securitylab.ai_contract import request
        event=threading.Event();fake=DockerTransport()
        def executor(argv,cwd,limits,**kwargs):
            if 'start' in argv:
                event.set();self.assertTrue(kwargs['stop']())
                return response(code=-9,cancelled=True)
            return fake(argv,cwd,limits,**kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            adapter=HermesAdapter(root,root/'calls',executor=executor)
            with self.assertRaises(PolicyError):adapter.ask(request('smoke'),stop=event.is_set)
            receipt=json.loads(next((root/'calls').glob('*.json')).read_text())
            self.assertEqual(receipt['status'],'CANCELLED')
            self.assertEqual(receipt['cleanup'],'PASS')
        self.assertTrue(any('rm' in c for c in fake.calls))

class PersistenceAndDiffTests(unittest.TestCase):
    setUp=dashboard_fixture.DashboardTests.setUp
    def test_diff_endpoint_is_bounded_to_one_run_and_candidate_number(self):
        rid='a'*32; folder=self.app.root/'access_ai'/rid;folder.mkdir(parents=True)
        (folder/'summary.json').write_text(json.dumps({'status':'BLOCKED','candidates':[{}]}))
        (folder/'candidate_1.patch').write_text('--- a/app/main.py\n+++ b/app/main.py\n+change\n')
        result=self.app.dispatch('GET',f'/api/runs/{rid}/attempts/1/diff')
        self.assertIn('+change',result['content'])
        self.assertEqual(self.app.run(rid)['attempts'][0]['diff'],result['content'])
        with self.assertRaises(PolicyError): self.app.dispatch('GET',f'/api/runs/{rid}/attempts/3/diff')
        with self.assertRaises(PolicyError): self.app.dispatch('GET',f'/api/runs/{rid}/patch')

    def test_restart_does_not_leave_waiting_stage_or_claim_cancelled(self):
        from securitylab.dashboard import Dashboard
        import time
        rid='b'*32
        self.app.save_job(dict(id=rid,status='RUNNING',created=time.time(),input=self.inp))
        c=RunControl(self.app.jobs/(rid+'.live.json'));c.emit('red','wait_model','waiting');c.cancel()
        fresh=Dashboard(self.app.root,self.profiles,self.policies)
        result=fresh.run(rid)
        self.assertEqual(result['exec'],'blocked')
        self.assertFalse(result['cancelSupported'])
        self.assertTrue(all(r['state'] not in ('running','wait_model') for r in result['stages']))
        self.assertIn('INTERRUPTED',result['events'][-1]['text'])
