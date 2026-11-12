"""S7.3: policy regressions, null actor, bounded AI workflow; mocked Docker/AI."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from securitylab.access_baseline import validate_policy, _classify
from securitylab.access_contract import make_request, validate_reply
from securitylab.access_ai import run_access_ai
from securitylab.policy import PolicyError
import test_access_ai as ai_tests
from test_access_ai import FakeHermes, FIX, HERE
import test_access_baseline as baseline_tests

EXTENDED=HERE/'examples/security_policies/record_ownership_extended.json'

class ExtendedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy=json.loads(EXTENDED.read_text('utf-8'))

    def test_extended_policy_accepted_old_policy_unchanged(self):
        validate_policy(self.policy)
        validate_policy(json.loads((HERE/'examples/security_policies/record_ownership.json').read_text('utf-8')))
        self.assertEqual(len(self.policy['checks']),8)

    def test_reject_ambiguous_or_unsafe_extended_policy(self):
        bad=[]
        v=copy.deepcopy(self.policy);v['schema_version']=1;bad.append(v)
        for field,value in [('actor',False),('actor','alice\r\nX: y'),('expected_status',200),('expected_body_sha256','bad')]:
            v=copy.deepcopy(self.policy);v['checks'][4][field]=value;bad.append(v)
        v=copy.deepcopy(self.policy);v['checks'].append(dict(v['checks'][-1],id='extra'));bad.append(v)
        v=copy.deepcopy(self.policy);v['checks'][0]['actor']=None;bad.append(v)
        for value in bad:
            with self.subTest(value=value),self.assertRaises(PolicyError):validate_policy(value)

    def test_ai_contract_supports_regressions_but_red_cannot_select_them(self):
        hints=[{k:c[k] for k in ('id','kind','actor','path','expected_status')} for c in self.policy['checks']]
        req=make_request('red','app/main.py',FIX,hints)
        with self.assertRaises(PolicyError):
            validate_reply(req,{'file':'app/main.py','description':'test','check_id':'anonymous-one'})
        with self.assertRaises(PolicyError):
            make_request('blue','app/main.py',FIX,hints,finding='owner-missing')

class ExtendedWorkflowTests(unittest.TestCase):
    def setUp(self):
        ai_tests.AccessAIFixture.setUp(self)
        self.policy.write_bytes(EXTENDED.read_bytes())

    run_ai=ai_tests.AccessAIFixture.run_ai

    def test_correct_candidate_preserves_all_eight_cases(self):
        result=self.run_ai()
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(result['checks_total'],8)
        self.assertTrue(all(x['passed'] for x in result['stages']['recheck']['observations']))
        self.assertEqual([x['actual_status'] for x in result['stages']['recheck']['observations']],
                         [200,200,403,403,401,401,404,403])

    def test_failure_then_correction_uses_eight_case_evidence(self):
        FakeHermes.blue_text=[(self.src/'app/main.py').read_text('utf-8')+'\n# cosmetic\n',FIX]
        result=self.run_ai()
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(len(FakeHermes.calls[-1]['evidence']),8)
        self.assertEqual(result['blue_attempts_used'],2)

    def test_regression_failures_never_fixed_or_retried(self):
        prior=self.observer
        for index,status,body in [(4,200,b'leak'),(5,404,b'not-found'),(6,403,b'forbidden'),(4,401,b'leak-with-401')]:
            def observer(folder,*args,**kw):
                result=prior(folder,*args,**kw)
                if folder.name=='candidate':
                    row=result['observations'][index]
                    row.update(actual_status=status,passed=status==row['expected_status'],
                               body_bytes=len(body),body_sha256=hashlib.sha256(body).hexdigest())
                return result
            with self.subTest(index=index,status=status):
                result=run_access_ai(self.store,self.sid,'app/main.py',self.policy,
                    execute=True,adapter_factory=FakeHermes,observer=observer)
                self.assertEqual(result['status'],'NEEDS_REVIEW',result)
                self.assertIsNone(result['finding_status'])
                self.assertNotIn('git',result)
                self.assertEqual(len(FakeHermes.calls),2)
                self.assertNotIn('recheck',result['stages'])

    def test_baseline_regression_failure_stops_before_blue(self):
        data=json.loads(self.policy.read_text('utf-8'))
        data['checks'][4]['expected_body_sha256']='0'*64
        self.policy.write_text(json.dumps(data),encoding='utf-8')
        result=self.run_ai()
        self.assertEqual(result['status'],'NEEDS_REVIEW',result)
        self.assertEqual(len(FakeHermes.calls),1)

class ExtendedBrokerTests(unittest.TestCase):
    def setUp(self):
        baseline_tests.AccessBaselineTests.setUp(self)
        self.policy_file.write_bytes(EXTENDED.read_bytes())
    snapshot=baseline_tests.AccessBaselineTests.snapshot
    factory=baseline_tests.AccessBaselineTests.factory
    probe=baseline_tests.AccessBaselineTests.probe

    def test_broker_accepts_null_actor_and_validates_evidence(self):
        report=self.probe()
        self.assertEqual(report['status'],'ACCESS_POLICY_VIOLATION_REPRODUCED',report)
        self.assertIsNone(report['observations'][4]['actor'])
        self.fake.vulnerable=False
        report=self.probe()
        self.assertEqual(report['status'],'ACCESS_POLICY_MATCHED',report)

if __name__=='__main__':unittest.main()
