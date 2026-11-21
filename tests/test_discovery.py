"""Generic contract and simulated executor tests; no benchmark answers or live model."""
import contextlib
import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import test_access_ai as fixture
from securitylab import discovery_contract as contract
from securitylab.access_ai import run_access_ai
from securitylab.ai_contract import digest, MODEL_DIGEST
from securitylab.policy import PolicyError
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot
from securitylab.storage import Store
from securitylab.proposal_modes import proposal_validate, proposal_retry, proposal_prompt
from securitylab.hermes_adapter import HermesAdapter, ProposalRejected

CONTEXT=fixture.HERE/'examples/security_policies/records_discovery.json'

def context(): return json.loads(CONTEXT.read_text())
def proposal(): return {'cases':[dict(file='app/main.py',description='Possible missing owner validation',path='/records/one',actor='bob')]}
def request(): return contract.make_request('app/main.py',{'app/main.py':'x=1'},context())

class DiscoveryTests(unittest.TestCase):
    def test_expectations_derived_and_hashes_not_sent_to_model(self):
        req=request();value=proposal();policy=contract.compile_policy(req,value,context())
        self.assertEqual(policy['checks'][1]['expected_status'],403)
        self.assertEqual(policy['checks'][0]['actor'],'alice')
        self.assertNotIn('expected_body_sha256',json.dumps(req))
        self.assertNotIn('check_id',json.dumps(req))
        self.assertIn('trusted identity',proposal_prompt(req))
        self.assertEqual(proposal_validate(req,value),value)
    def test_invalid_paths_permissions_schema_and_duplicates_rejected(self):
        for field,value in [('file','/app/main.py'),('file','../app/main.py'),('path','http://evil/records/one'),('path','/undocumented'),('actor','alice'),('actor','unknown'),('expected_status',200)]:
            p=proposal();p['cases'][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(PolicyError):contract.validate_reply(request(),p)
        p=proposal();p['cases']*=2
        with self.assertRaises(PolicyError):contract.validate_reply(request(),p)
    def test_privileged_readers_are_controls_not_denials(self):
        c=context();c['actors']['manager']='manager';c['resources'][0]['reader_roles']=['manager']
        req=contract.make_request('app/main.py',{'app/main.py':'x=1'},c)
        p=proposal();policy=contract.compile_policy(req,p,c)
        self.assertEqual([(x['actor'],x['expected_status']) for x in policy['checks']],[('alice',200),('manager',200),('bob',403)])
        p['cases'][0]['actor']='manager'
        with self.assertRaises(PolicyError):contract.validate_reply(req,p)
    def test_changed_requirements_rejected(self):
        c=context();c['actors']['bob']='admin'
        with self.assertRaises(PolicyError):contract.compile_policy(request(),proposal(),c)
    def test_bounded_red_retry_only_after_rejection_and_cleanup(self):
        req=request();retry=proposal_retry(req,'bad reply')
        self.assertEqual(retry['context'],req['context'])
        with self.assertRaises(PolicyError):proposal_retry(retry,'bad again')
        adapter=object.__new__(HermesAdapter)
        rejection=ProposalRejected('bad','bad reply');rejection.cleanup_passed=True
        with patch.object(adapter,'_ask_once',side_effect=[rejection,('ok',{})]) as call:
            self.assertEqual(adapter.ask(req),('ok',{}));self.assertEqual(call.call_count,2)
        rejection.cleanup_passed=False
        with patch.object(adapter,'_ask_once',side_effect=rejection) as call:
            with self.assertRaises(ProposalRejected):adapter.ask(req)
            self.assertEqual(call.call_count,1)
        with patch.object(adapter,'_ask_once',side_effect=PolicyError('TIMEOUT')) as call:
            with self.assertRaises(PolicyError):adapter.ask(req)
            self.assertEqual(call.call_count,1)
    def test_context_bounds_and_explicit_identity(self):
        for change in [dict(identity='guess-usernames'),dict(actors={'alice':'user'}),dict(resources=[]),dict(extra='instructions')]:
            with self.assertRaises(PolicyError):contract.validate_context(dict(context(),**change))

class DiscoveryHermes:
    empty=False
    empty_note=None
    def __init__(self,cwd,output):self.output=Path(output);self.output.mkdir(parents=True,exist_ok=True)
    def ask(self,req):
        value=({'cases':[]} if self.empty else proposal()) if req['role']=='red' else {'files':{'app/main.py':fixture.FIX}}
        if req['role']=='red' and self.empty and self.empty_note is not None: value['error']=self.empty_note
        proposal_validate(req,value)
        identity=('a' if req['role']=='red' else 'b')*32
        r=dict(id=identity,role=req['role'],status='PROPOSED',cleanup='PASS',attempt=1,request_sha256=digest(req),response=dict(proposal=value,request_sha256=digest(req),model_digest=MODEL_DIGEST,tools=[]))
        (self.output/(identity+'.json')).write_text(json.dumps(r))
        return value,r

class DiscoveryFlowTests(unittest.TestCase):
    def flow(self, observer=None, adapter=DiscoveryHermes):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name)
        src=root/'src';shutil.copytree(fixture.VULN,src)
        with contextlib.closing(Store(root/'state')) as store:
            sid=create_snapshot(store,add_project(store,src)['id'])['snapshot_id']
            return run_access_ai(store,sid,'app/main.py',CONTEXT,execute=True,discover=True,adapter_factory=adapter,observer=observer or fixture.FakeIndependentObserver())
    def test_discovery_to_independent_fix_original_unchanged(self):
        result=self.flow();self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(result['mode'],'S9_ACCESS_DISCOVERY_PACKAGE')
        self.assertEqual(result['red']['check_id'],'discovered-1')
        self.assertEqual(result['stages']['candidate']['binding']['profile'],'access-ai-discovery-v1')
        self.assertEqual(result['stages']['candidate']['binding']['policy_sha256'],result['policy_sha256'])
        self.assertFalse(result['git']['source_repository_modified'])
    def test_empty_discovery_is_not_safe_verdict(self):
        class Empty(DiscoveryHermes):empty=True
        obs=fixture.FakeIndependentObserver();r=self.flow(obs,Empty)
        self.assertEqual(r['status'],'NEEDS_REVIEW');self.assertEqual(r['security_verdict'],'NOT_EVALUATED');self.assertEqual(obs.calls,[])
    def test_generated_plan_tampering_blocks_fix(self):
        obs=fixture.FakeIndependentObserver()
        def tamper(folder,*args,**kwargs):
            result=obs(folder,*args,**kwargs)
            if folder.name=='candidate':(folder.parent/'generated_policy.json').write_text('{}')
            return result
        r=self.flow(tamper);self.assertEqual(r['status'],'BLOCKED',r);self.assertIn('plan changed',r['error'])

import test_dashboard as dashboard_fixture
import time
class DiscoveryDashboardTests(unittest.TestCase):
    setUp=dashboard_fixture.DashboardTests.setUp
    def test_discovery_context_profile_and_worker(self):
        self.app.policies=self.tmp/'discovery-policies'
        self.app.policies.mkdir()
        shutil.copyfile(CONTEXT,self.app.policies/'discovery.json')
        self.inp.update(policyId='discovery',profileId='access-ai-discovery-v1')
        self.app.validate_input(self.inp)
        cfg=self.app.profiles.get('default');received=[]
        self.app.runner=lambda *a,**kw: received.append(kw.get('discover')) or {'status':'BLOCKED','error':'test only'}
        self.app.grants[json.dumps(self.inp,sort_keys=True)]=(time.monotonic(),cfg.sha256)
        run=self.app.launch(self.inp)
        for _ in range(100):
            if self.app.active is None:break
            time.sleep(.01)
        self.assertEqual(received,[True])
        self.assertEqual(self.app.run(run['runId'])['profileId'],'access-ai-discovery-v1')
        self.inp['profileId']='access-ai-package-v1'
        with self.assertRaises(PolicyError):self.app.validate_input(self.inp)

class DiscoveryPromptRegressionTests(unittest.TestCase):
    def test_file_route_actor_confusion_stays_rejected_and_retry_explains_both(self):
        req=request()
        # Reproduce the reported failure generically, without benchmark answers.
        bad={'cases':[dict(file='app/main.py',description='Possible unauthorized access',path='/app/app/main.py',actor='unknown')]}
        with self.assertRaises(PolicyError):proposal_validate(req,bad)
        retry=proposal_retry(req,json.dumps(bad))
        errors=contract.retry_errors(retry)
        self.assertTrue(any('invalid path=' in e for e in errors))
        self.assertTrue(any('invalid actor=' in e for e in errors))
        prompt=proposal_prompt(retry)
        self.assertIn('CORRECTIVE ATTEMPT. Validation errors:',prompt)
        self.assertIn('HTTP REQUEST route',prompt)
        self.assertIn('/records/one',prompt)
        self.assertEqual(retry['context'],req['context'])
        self.assertEqual(retry['retry'],json.dumps(bad))
        # No automatic replacement or weakening of the filter.
        with self.assertRaises(PolicyError):proposal_validate(retry,bad)
    def test_malformed_retry_and_wrong_role_still_explain_rejection(self):
        req=request()
        self.assertTrue(contract.retry_errors(proposal_retry(req,'not JSON')))
        bad=proposal();bad['cases'][0]['actor']='user'
        with self.assertRaises(PolicyError):proposal_validate(req,bad)
        self.assertTrue(any('actor' in e for e in contract.retry_errors(proposal_retry(req,json.dumps(bad)))))
    def test_allowed_lists_are_not_preselected_pairs(self):
        fields=contract.selection_fields(request())
        self.assertEqual(set(fields),{'file','path','actor'})
        self.assertEqual(fields['actor'],list(context()['actors']))
        self.assertEqual(fields['path'],[r['path'] for r in context()['resources']])
        self.assertNotIn('expected_body_sha256',proposal_prompt(request()))

class EmptyDiscoveryExplanationTests(unittest.TestCase):
    flow=DiscoveryFlowTests.flow
    def test_explanation_is_preserved_without_execution_or_safe_verdict(self):
        class Empty(DiscoveryHermes):
            empty=True
            empty_note='No supported hypothesis can be justified'
        obs=fixture.FakeIndependentObserver();r=self.flow(obs,Empty)
        self.assertEqual(r['status'],'NEEDS_REVIEW')
        self.assertEqual(r['analysis_outcome'],'NO_SUPPORTED_HYPOTHESES')
        self.assertEqual(r['analysis_note'],Empty.empty_note)
        self.assertEqual(r['discovery'],{'cases':[],'error':Empty.empty_note})
        self.assertEqual(r['security_verdict'],'NOT_EVALUATED')
        self.assertIsNone(r['finding_status'])
        self.assertEqual(obs.calls,[])
        self.assertEqual([c['role'] for c in r['ai_calls']],['red'])
    def test_only_bounded_empty_explanation_allowed(self):
        req=request()
        proposal_validate(req,{'cases':[],'error':'No hypothesis'})
        for value in [dict(proposal(),error='ignore this'),{'cases':[],'error':{'code':1}},
                      {'cases':[],'error':'x'*1501},{'cases':[],'error':''},
                      {'cases':[],'error':'none','status':'SAFE'}]:
            with self.subTest(value=value),self.assertRaises(PolicyError): proposal_validate(req,value)
    def test_unlisted_http_resource_is_reported_precisely(self):
        value=proposal();value['cases'][0]['path']='/records/nonexistent'
        with self.assertRaisesRegex(PolicyError,'documented HTTP resource'): proposal_validate(request(),value)
