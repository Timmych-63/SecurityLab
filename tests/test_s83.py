"""Dashboard result plumbing; synthetic executor, no claim of model/Docker acceptance."""
import json
import time
import unittest
import test_dashboard as fixture
from securitylab.policy import PolicyError
from securitylab.dashboard import Dashboard

class ResultFlowTests(unittest.TestCase):
    setUp = fixture.DashboardTests.setUp

    def execute(self, status, error=None):
        def runner(store, sid, entry, policy, **kw):
            kw['progress']('candidate', 'done', 'ACCESS_POLICY_VIOLATION_REPRODUCED' if status=='BLOCKED' else 'ACCESS_POLICY_MATCHED')
            result={'status':status,'snapshot_id':sid,'error':error,'stages':{},
                    'security_verdict':'NOT_EVALUATED','finding_status':None}
            if status=='PASS':
                result.update(finding_status='FIXED',security_verdict='POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX',
                    git={'diff':'--- a/app/main.py\n+++ b/app/main.py\n','verified_commit':'a'*40,'branch':'review'})
            folder=self.app.root/'access_ai'/kw['run_id']
            folder.mkdir(parents=True,exist_ok=True)
            (folder/'summary.json').write_text(json.dumps(result),encoding='utf-8')
            return result
        self.app.runner=runner
        cfg=self.app.profiles.get('default')
        self.app.grants[json.dumps(self.inp,sort_keys=True)]=(time.monotonic(),cfg.sha256)
        identity=self.app.dispatch('POST','/api/runs',self.inp)['runId']
        for _ in range(300):
            if self.app.active is None: break
            time.sleep(.01)
        self.assertIsNone(self.app.active)
        return identity

    def test_blocked_reason_persisted_in_job_live_detail_and_after_restart(self):
        reason='blue attempt 2: TIMEOUT <not html>'
        identity=self.execute('BLOCKED',reason)
        row=self.app.dispatch('GET','/api/runs/'+identity)
        self.assertEqual(row['error'],reason)
        self.assertIn(reason,row['events'][-1]['text'])
        self.assertEqual(row['stages'][-1]['state'],'failed')
        saved=json.loads((self.app.jobs/(identity+'.json')).read_text())
        self.assertEqual(saved['error'],reason)
        with self.assertRaises(PolicyError): self.app.dispatch('GET','/api/runs/'+identity+'/patch')
        again=Dashboard(self.app.root,self.profiles,self.policies)
        self.assertIn(reason,again.run(identity)['events'][-1]['text'])

    def test_pass_can_export_saved_patch_and_evidence(self):
        identity=self.execute('PASS')
        row=self.app.dispatch('GET','/api/runs/'+identity)
        self.assertEqual(row['exec'],'completed')
        self.assertEqual(row['finding'],'FIXED')
        self.assertIn(identity,[r['id'] for r in self.app.dispatch('GET','/api/runs')])
        patch=self.app.dispatch('GET','/api/runs/'+identity+'/patch')
        self.assertIn('+++ b/app/main.py',patch['content'])
        artifact=self.app.dispatch('GET','/api/runs/'+identity+'/artifacts/summary.json')
        self.assertEqual(json.loads(artifact['content'])['status'],'PASS')
        self.assertNotIn('Причина:',row['events'][-1]['text'])

if __name__=='__main__': unittest.main()
