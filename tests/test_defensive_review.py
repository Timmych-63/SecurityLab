"""Defensive protocol and real Git, simulated model/Docker observations."""
import contextlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import test_access_ai as fixture
from securitylab import app_map, review_contract as contract
from securitylab.defensive_review import run_defensive_review
from securitylab.ai_contract import digest, MODEL_DIGEST
from securitylab.proposal_modes import proposal_validate, proposal_prompt, proposal_retry
from securitylab.policy import PolicyError
from securitylab.storage import Store
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot

CONTEXT=fixture.HERE/'examples/security_policies/records_defensive.json'
def context():return json.loads(CONTEXT.read_text())
def sources():return {str(p.relative_to(fixture.VULN)):p.read_text() for p in fixture.VULN.rglob('*.py')}
def request(role='red'):
    files=sources()
    return contract.make_request(role,'app/main.py',files,context(),app_map.inventory(files,'app/main.py'),review=[dict(file='app/main.py',description='Code clarity',recommendation='Add a module comment')])

class ContractTests(unittest.TestCase):
    def test_only_read_and_search_actions_no_http_shell_or_generated_tests(self):
        req=request()
        for action in [{'action':'read','file':'app/main.py','start':1,'count':40},{'action':'search','query':'FastAPI'},{'review':[],'note':'No changes'}]:proposal_validate(req,action)
        for action in [{'action':'probe','path':'/records/one','actor':'alice'},{'action':'shell','command':'echo test'},{'cases':[]},{'action':'read','file':'../secret','start':1,'count':40},{'action':'read','file':'app/main.py','start':True,'count':1}]:
            with self.subTest(action=action),self.assertRaises(PolicyError):proposal_validate(req,action)
        self.assertIn('No attacks',proposal_prompt(req))
    def test_patch_cannot_add_or_change_external_files(self):
        req=request('blue')
        proposal_validate(req,{'files':{'app/main.py':req['files']['app/main.py']+'\n# clarity\n'}})
        for value in [{'files':{'tests/test_new.py':'x=1'}},{'files':{'../other.py':'x=1'}},{'files':{'app/main.py':req['files']['app/main.py']}},{'files':{'app/main.py':'invalid python !'}}]:
            with self.assertRaises(PolicyError):proposal_validate(req,value)
    def test_operator_plan_has_only_authorized_reads_and_standard_regressions(self):
        ctx=context();plan=contract.regression_plan(ctx)
        for policy in plan:
            for c in policy['checks']:
                self.assertNotEqual(c['kind'],'deny')
                if c['kind']=='control':self.assertEqual(c['actor'],next(r for r in ctx['resources'] if r['path']==c['path'])['owner'])
        with self.assertRaises(PolicyError):contract.validate_context(dict(ctx,regressions=[dict(ctx['regressions'][0],expected_status=403)]))
    def test_static_map_no_execution_and_unsupported_dependency(self):
        files=sources();files['app/main.py']='raise RuntimeError("MUST NOT EXECUTE")\n'+files['app/main.py']
        mapping=app_map.inventory(files,'app/main.py')
        self.assertTrue(mapping['routes']);self.assertIn('functions',mapping['files'][0])
        files['app/main.py']='import unknown_dependency\n'+files['app/main.py']
        with self.assertRaisesRegex(PolicyError,'Dependencies'):app_map.inventory(files,'app/main.py')
    def test_unknown_resource_and_dynamic_router_fail_closed(self):
        mapping=app_map.inventory(sources(),'app/main.py');ctx=context();ctx['resources'][0]['path']='/unknown'
        with self.assertRaises(PolicyError):app_map.check_resources(mapping,ctx)
        files=sources();files['app/main.py']+='\napp.include_router(other)\n'
        with self.assertRaisesRegex(PolicyError,'Router'):app_map.inventory(files,'app/main.py')
    def test_retry_is_bounded_preserves_context(self):
        req=request();retry=proposal_retry(req,'invalid response')
        self.assertEqual(req['context'],retry['context'])
        with self.assertRaises(PolicyError):proposal_retry(retry,'again')

class ReviewModel:
    actions=[{'action':'search','query':'read_record'}, {'action':'read','file':'app/main.py','start':1,'count':40}, {'review':[dict(file='app/main.py',description='Module lacks a purpose comment',recommendation='Add a concise descriptive comment')]}]
    wrong_patch=False
    requests=[]
    def __init__(self,cwd,output):self.output=Path(output);self.output.mkdir(parents=True,exist_ok=True);self.n=0;self.requests=[];type(self).requests=self.requests
    def ask(self,req):
        self.requests.append(req);self.n+=1
        if req['role']=='red':value=self.actions[min(self.n-1,len(self.actions)-1)]
        else:
            text=req['files']['app/main.py']+'\n# Records API: application handlers.\n'
            if self.wrong_patch:text=text.replace('synthetic-A','changed-value')
            value={'files':{'app/main.py':text}}
        proposal_validate(req,value)
        identity=f'{self.n:032x}'
        r=dict(id=identity,role=req['role'],status='PROPOSED',cleanup='PASS',attempt=2 if 'retry' in req else 1,request_sha256=digest(req),response=dict(proposal=value,request_sha256=digest(req),model_digest=MODEL_DIGEST,tools=[]))
        (self.output/(identity+'.json')).write_text(json.dumps(r))
        return value,r

class FlowTests(unittest.TestCase):
    def setup_flow(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name)
        src=root/'src';shutil.copytree(fixture.VULN,src)
        store=Store(root/'state');self.addCleanup(store.db.close)
        sid=create_snapshot(store,add_project(store,src)['id'])['snapshot_id']
        return store,sid,src
    def run_flow(self,adapter=ReviewModel,observer=None,**kw):
        store,sid,src=self.setup_flow()
        result=run_defensive_review(store,sid,'app/main.py',CONTEXT,execute=True,adapter_factory=adapter,observer=observer or fixture.FakeIndependentObserver(),**kw)
        self.assertEqual((src/'app/main.py').read_text(),(fixture.VULN/'app/main.py').read_text())
        return result
    def test_full_read_search_patch_regression_and_recheck(self):
        obs=fixture.FakeIndependentObserver();r=self.run_flow(observer=obs)
        self.assertEqual(r['status'],'PASS',r)
        self.assertEqual(obs.calls,['baseline','candidate','recheck'])
        self.assertEqual(r['review_outcome'],'PATCH_PASSED_FUNCTIONAL_TESTS')
        self.assertEqual(r['security_verdict'],'NOT_EVALUATED');self.assertIsNone(r['finding_status'])
        self.assertFalse(r['git']['merged']);self.assertEqual(len(r['ai_calls']),4)
        self.assertEqual(ReviewModel.requests[1]['history'][0]['action']['action'],'search')
        self.assertIn('text',ReviewModel.requests[2]['history'][1]['result'])
    def test_bad_readiness_never_calls_model(self):
        obs=fixture.FakeIndependentObserver();obs.fail_stage='baseline'
        class NoModel:
            def __init__(self,*a):raise AssertionError('Model must not be called')
        r=self.run_flow(NoModel,obs);self.assertEqual(r['status'],'BLOCKED');self.assertEqual(r['ai_calls'],[])
    def test_empty_review_never_calls_blue(self):
        class Empty(ReviewModel):actions=[{'review':[],'note':'No justified changes'}]
        r=self.run_flow(Empty);self.assertEqual(r['status'],'NEEDS_REVIEW');self.assertEqual(r['candidates'],[])
        self.assertEqual([c['role'] for c in r['ai_calls']],['red'])
    def test_regression_failure_does_not_commit(self):
        obs=fixture.FakeIndependentObserver()
        def failed(folder,*a,**kw):
            result=obs(folder,*a,**kw)
            if folder.name in ('candidate','candidate_retry'):result['observations'][0]['body_sha256']='0'*64
            return result
        r=self.run_flow(observer=failed)
        self.assertEqual(r['status'],'NEEDS_REVIEW',r);self.assertNotIn('git',r);self.assertEqual(len(r['candidates']),2)
    def test_recheck_failure_does_not_commit(self):
        obs=fixture.FakeIndependentObserver();obs.fail_stage='recheck'
        r=self.run_flow(observer=obs);self.assertEqual(r['status'],'BLOCKED');self.assertNotIn('git',r)
    def test_plan_tampering_blocks(self):
        obs=fixture.FakeIndependentObserver()
        def modified(folder,*a,**kw):
            result=obs(folder,*a,**kw)
            if folder.name=='candidate':(folder.parent/'functional_plan.json').write_text('[]')
            return result
        r=self.run_flow(observer=modified);self.assertEqual(r['status'],'BLOCKED');self.assertIn('plan modified',r['error'])
    def test_cancel_before_execution(self):
        r=self.run_flow(stop=lambda:True);self.assertEqual(r['status'],'STOPPED');self.assertEqual(r['ai_calls'],[])
    def test_decision_budget_is_enforced(self):
        class Endless(ReviewModel):actions=[{'action':'search','query':'app'}]
        r=self.run_flow(Endless);self.assertEqual(r['status'],'BLOCKED');self.assertEqual(len(r['ai_calls']),5)

import test_dashboard as dashboard_fixture
import time
from securitylab.dashboard_dto import run_view
class DashboardTests(unittest.TestCase):
    setUp=dashboard_fixture.DashboardTests.setUp
    def test_profile_dispatches_defensive_worker(self):
        self.app.policies=self.tmp/'review-policies';self.app.policies.mkdir()
        shutil.copyfile(CONTEXT,self.app.policies/'review.json')
        self.inp.update(policyId='review',profileId=contract.PROFILE)
        self.app.validate_input(self.inp)
        cfg=self.app.profiles.get('default');self.app.grants[json.dumps(self.inp,sort_keys=True)]=(time.monotonic(),cfg.sha256)
        with patch('securitylab.defensive_review.run_defensive_review',return_value={'status':'NEEDS_REVIEW','error':'Test only'}) as runner:
            r=self.app.launch(self.inp)
            for _ in range(100):
                if self.app.active is None:break
                time.sleep(.01)
            runner.assert_called_once();self.assertNotIn('discover',runner.call_args.kwargs)
        self.assertEqual(self.app.run(r['runId'])['profileId'],contract.PROFILE)
    def test_all_regression_batches_are_visible_and_no_fixed_claim(self):
        obs=dict(path='/records/one',actor='alice',expected_status=200,actual_status=200,passed=True)
        stages={name:dict(status='ACCESS_POLICY_MATCHED',observations=[obs]) for name in ('baseline','baseline_2','candidate','candidate_2','recheck','recheck_2')}
        result=run_view(dict(mode='S10_DEFENSIVE_REVIEW',status='PASS',stages=stages,candidates=[{}]),'a'*32,self.tmp)
        self.assertEqual(len(result['checks']),2)
        self.assertEqual(result['finding'],None);self.assertEqual(result['verdict'],'NOT_EVALUATED')
        self.assertTrue(all(c['final']=='pass' for c in result['checks']))
