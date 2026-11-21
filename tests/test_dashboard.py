import contextlib
import functools
import http.client
import json
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from securitylab.dashboard import Dashboard, Handler, ThreadingHTTPServer, bounded
from securitylab.dashboard_dto import run_view
from securitylab.dashboard_profiles import Profiles
from securitylab.ai_config import AIConfig
from securitylab.policy import PolicyError
from securitylab.storage import Store
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot

ROOT=Path(__file__).resolve().parents[1]

class DashboardTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.tmp=Path(tmp.name)
        self.profiles=self.tmp/'profiles'; self.profiles.mkdir()
        self.policies=ROOT/'examples/security_policies'
        self.app=Dashboard(self.tmp/'state',self.profiles,self.policies)
        self.src=self.tmp/'project'; shutil.copytree(ROOT/'examples/s7_repos/authz_vulnerable',self.src)
        with contextlib.closing(Store(self.app.root)) as s:
            pid=add_project(s,self.src)['id']; sid=create_snapshot(s,pid)['snapshot_id']
        self.inp=dict(projectId=pid,snapshotId=sid,service='.',entryModule='app/main.py',
            profileId='access-ai-s72-v1',policyId='record_ownership',aiConfigId='default',stateDir=str(self.app.root))

    def profile(self,model='other:2b'):
        (self.profiles/'other.toml').write_text('[ai]\nmodel = "'+model+'"\nmodel_digest = "'+'a'*64+'"\n',encoding='utf-8')

    def test_catalog_validates_operator_profiles_and_digest(self):
        self.profile()
        rows=self.app.profiles.list()
        self.assertEqual(rows[1]['model'],'other:2b'); self.assertIsNone(rows[1]['present'])
        with self.assertRaises(PolicyError): self.app.profiles.get('../secret')
        (self.profiles/'other.toml').write_text('[ai]\ncontext_tokens=8192')
        with self.assertRaises(PolicyError): self.app.profiles.get('other')

    def test_run_pins_selected_config_and_does_not_use_env(self):
        self.profile(); self.inp['aiConfigId']='other'
        entered=threading.Event(); release=threading.Event(); self.addCleanup(release.set)
        received=[]
        def runner(store,sid,entry,policy,**kw):
            received.append(kw['adapter_factory'].keywords['config']); entered.set(); release.wait(3)
            return {'status':'BLOCKED'}
        self.app.runner=runner
        cfg=self.app.profiles.get('other')
        self.app.grants[json.dumps(self.inp,sort_keys=True)]=(time.monotonic(),cfg.sha256)
        result=self.app.launch(self.inp); self.assertTrue(entered.wait(3))
        self.profile('new:2b')
        self.assertEqual(received[0].model,'other:2b')
        saved=json.loads((self.app.jobs/(result['runId']+'.json')).read_text())
        self.assertEqual(saved['ai_config']['model'],'other:2b')
        self.assertEqual(saved['input']['aiConfigId'],'other')
        release.set()
        for _ in range(100):
            if self.app.active is None: break
            time.sleep(.01)
        self.assertIsNone(self.app.active)

    def test_changed_profile_and_missing_preflight_block_launch(self):
        self.profile(); self.inp['aiConfigId']='other'
        with self.assertRaises(PolicyError): self.app.launch(self.inp)
        cfg=self.app.profiles.get('other')
        self.app.grants[json.dumps(self.inp,sort_keys=True)]=(time.monotonic(),cfg.sha256)
        self.profile('new:2b')
        with self.assertRaises(PolicyError): self.app.launch(self.inp)
        self.assertEqual(list(self.app.jobs.glob('*.json')),[])

    def test_snapshot_binding_and_path_not_client_controlled(self):
        self.inp['stateDir']=str(self.tmp)
        with self.assertRaises(PolicyError): self.app.validate_input(self.inp)
        with self.assertRaises(PolicyError): bounded(self.tmp/'secret',self.app.root)
        with self.assertRaises(PolicyError): self.app.policy('../../secret')

    def test_no_fake_cancel_or_patch(self):
        with self.assertRaises(PolicyError): self.app.dispatch('POST','/api/runs/'+'a'*32+'/cancel')
        with self.assertRaises(FileNotFoundError): self.app.run('a'*32)

    def test_restart_marks_unfinished_job_interrupted(self):
        job=dict(id='b'*32,status='RUNNING',created=time.time(),input=self.inp)
        self.app.save_job(job)
        restarted=Dashboard(self.app.root,self.profiles,self.policies)
        r=restarted.run('b'*32)
        self.assertEqual(r['exec'],'blocked'); self.assertIsNone(r['finding'])

    def test_summary_preserves_pass_blocked_and_unperformed_recheck(self):
        obs=dict(actor='alice',path='/records/two',expected_status=403,actual_status=200,passed=False)
        raw=dict(status='BLOCKED',security_verdict='NOT_EVALUATED',finding_status=None,stages={'baseline':{'observations':[obs]}})
        r=run_view(raw,'a'*32,self.app.root)
        self.assertEqual(r['exec'],'blocked');self.assertEqual(r['checks'][0]['final'],'not_run')
        raw.update(status='PASS',security_verdict='POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX',finding_status='FIXED')
        r=run_view(raw,'a'*32,self.app.root)
        self.assertEqual(r['exec'],'completed');self.assertEqual(r['finding'],'FIXED')
        self.assertEqual(r['verdict'],raw['security_verdict'])

    def test_research_hypothesis_view_maps_stage_identifiers(self):
        # S11.3: the UI explains the empty 'Свежий стенд' cell for consistent
        # hypotheses and names the stages that produced each status (run #6).
        raw=dict(mode='S11_RESEARCH_CYCLE',status='DONE',security_verdict='NOT_EVALUATED',
                 finding_status=None,stages={},hypotheses=[
            dict(n=1,file='app/main.py',path='/records/one',actor=None,description='d',
                 expected_status=403,basis='b',observed_status=200,observed_stage='http_01',
                 confirm_status=None,confirm_stage=None,state='consistent')])
        r=run_view(raw,'a'*32,self.app.root)
        h=r['hypotheses'][0]
        self.assertEqual(h['observedStage'],'http_01')
        self.assertIsNone(h['confirmStage'])
        self.assertEqual(h['state'],'consistent')
        confirmed=dict(raw,hypotheses=[dict(raw['hypotheses'][0],state='confirmed',
                 confirm_status=200,confirm_stage='confirm')])
        h=run_view(confirmed,'a'*32,self.app.root)['hypotheses'][0]
        self.assertEqual(h['confirmStage'],'confirm')

    def test_project_read_model_and_snapshot_ids(self):
        p=self.app.project_rows()[0]
        self.assertTrue(p['supported'])
        self.assertEqual(p['snapshots'][0]['id'],self.inp['snapshotId'])
        self.assertIn('app/main.py',[e['entryFile'] for e in p['services']])

    def test_manifest_free_snapshot_is_offered_but_admission_still_required(self):
        with contextlib.closing(Store(self.app.root)) as store:
            store.db.execute('UPDATE projects SET inventory_json=? WHERE id=?',
                (json.dumps({'services':[], 'languages':{}}),self.inp['projectId']))
            store.db.commit()
        self.assertTrue(self.app.project_rows()[0]['supported'])
        self.inp['entryModule']='missing.py'
        with self.assertRaises(PolicyError): self.app.validate_input(self.inp)

    def test_non_python_project_not_promoted(self):
        other=self.tmp/'nodeproject';other.mkdir()
        (other/'package.json').write_text('{"name":"test"}')
        with contextlib.closing(Store(self.app.root)) as store:
            pid=add_project(store,other)['id']
            create_snapshot(store,pid)
        row=next(p for p in self.app.project_rows() if p['id']==pid)
        self.assertFalse(row['supported'])

    def test_http_same_origin_csrf_and_static_bootstrap(self):
        try: server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        except PermissionError: self.skipTest('Sandbox disallows sockets')
        server.app=self.app;server.token='test-token';server.dist=ROOT/'dashboard/dist'
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        port=server.server_port
        c=http.client.HTTPConnection('127.0.0.1',port,timeout=5);self.addCleanup(c.close)
        c.request('GET','/api/ai-configs');r=c.getresponse();self.assertEqual(r.status,200);self.assertEqual(json.loads(r.read())[0]['id'],'default')
        c.request('POST','/api/ai-configs/default/validate');r=c.getresponse();self.assertEqual(r.status,403);r.read()
        c.request('POST','/api/ai-configs/default/validate',headers={'Origin':f'http://127.0.0.1:{port}','X-CSRF-Token':'test-token'});r=c.getresponse();self.assertEqual(r.status,200);self.assertTrue(json.loads(r.read())['valid'])
        c.request('GET','/api/health',headers={'Host':'evil.example'});r=c.getresponse();self.assertEqual(r.status,403);r.read()
        c.request('GET','/');r=c.getresponse();self.assertIn(b'securitylab-core',r.read())

if __name__=='__main__': unittest.main()
