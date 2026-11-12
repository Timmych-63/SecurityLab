"""S7.2 tests: simulated external observer, real isolated Git, no Docker/model inference."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from securitylab.access_ai import run_access_ai
from securitylab.access_contract import make_request, validate_reply, prompt
from securitylab.ai_contract import MODEL_DIGEST, digest
from securitylab.cli import main
from securitylab.job_contract import parse_job
from securitylab.policy import PolicyError
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot
from securitylab.storage import Store

HERE=Path(__file__).resolve().parents[1]
VULN=HERE/'examples/s7_repos/authz_vulnerable'
FIX=(HERE/'examples/s7_repos/authz_fixed/app/main.py').read_text(encoding='utf-8')
POLICY=HERE/'examples/security_policies/record_ownership.json'


class FakeHermes:
    change = None
    red_case = 'outsider-one'
    blue_text = FIX
    calls = []
    def __init__(self,cwd,output):
        self.output=Path(output)
        self.output.mkdir(parents=True,exist_ok=True)
        self.calls=[]
        FakeHermes.calls=self.calls
    def ask(self, req):
        self.calls.append(req)
        if req['role']=='red':
            value={'file':req['entry'],'description':'Possible missing record ownership check',
                   'check_id':self.red_case}
        else:
            text = self.blue_text
            if isinstance(text, list):
                text = text[1 if 'evidence' in req else 0]
            elif 'evidence' in req:
                text += '\n# second proposal\n'
            value={'file':req['entry'],'content':text}
        validate_reply(req,value)
        identity='a'*32 if req['role']=='red' else ('c' if 'evidence' in req else 'b')*32
        record={'id':identity,'role':req['role'],'status':'PROPOSED',
                'cleanup':'PASS','request_sha256':digest(req),'attempt':2 if 'retry' in req else 1,
                'response':{'proposal':value,'request_sha256':digest(req),
                            'model_digest':MODEL_DIGEST,'tools':[]}}
        (self.output/(identity+'.json')).write_text(json.dumps(record),encoding='utf-8')
        return value, record


class FakeIndependentObserver:
    """Synthesized response hashes, not runtime Docker proof. stage receipts are mocked."""
    def __init__(self):
        self.calls=[]
        self.fail_stage=None
        self.tamper_receipt=None
        self.different_image=None
        self.policy_path=None
    def __call__(self, folder, payload, checks, binding, *, broker_factory, limits):
        stage=folder.name
        self.calls.append(stage)
        code=parse_job(payload)['files']['app/main.py']
        fixed="x_test_user != record['owner']" in code
        if self.policy_path and stage=='candidate':
            data=json.loads(self.policy_path.read_text(encoding='utf-8'))
            data['checks'][0]['expected_body_sha256']='0'*64
            self.policy_path.write_text(json.dumps(data),encoding='utf-8')
        if self.fail_stage==stage:
            raise PolicyError('Observer cleanup failed on '+stage)
        observations=[]
        for check in checks:
            key=check['path'].rsplit('/',1)[-1]
            owner='alice' if key=='one' else 'bob'
            control=check['actor']==owner
            status=(401 if check['actor'] is None else 404 if key not in ('one','two')
                    else 200 if (control or not fixed) else 403)
            data=(json.dumps({'id':key,'owner':owner,'value':'synthetic-A' if key=='one' else 'synthetic-B'},
                             separators=(',',':')).encode() if status==200 else json.dumps({'detail':{401:'Unauthorized',403:'Forbidden',404:'Not Found'}[status]},separators=(',',':')).encode())
            observations.append({'actor':check['actor'],'path':check['path'],
                'expected_status':check['expected_status'],'actual_status':status,
                'body_bytes':len(data),'body_truncated':False,
                'body_sha256':hashlib.sha256(data).hexdigest(),
                'passed':status==check['expected_status'],'error':None})
        receipt={'binding':binding,'stage':stage,'simulated':True}
        raw=json.dumps(receipt).encode()
        folder.mkdir(parents=True,exist_ok=True)
        (folder/'docker_receipt.json').write_bytes(raw)
        sha=hashlib.sha256(raw).hexdigest()
        if self.tamper_receipt==stage:
            # Tamper later on the final evidence re-read, not the mock response itself.
            self.tamper_path=folder/'docker_receipt.json'
        return {'status':'HTTP_CHECKS_PASSED' if all(x['passed'] for x in observations)
                 else 'HTTP_CHECKS_FAILED','observations':observations,
                'image_id':'sha256:'+'1'*64,
                'target_image_id':'sha256:'+('2' if self.different_image==stage else '1')*64,
                'cleanup':'PASS','receipt_sha256':sha}


class AccessAIFixture(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.src=self.root/'project'
        shutil.copytree(VULN,self.src)
        self.policy=self.root/'policy.json'
        self.policy.write_bytes(POLICY.read_bytes())
        self.store=Store(self.root/'state')
        self.addCleanup(self.store.close)
        self.pid=add_project(self.store,self.src,'Access test')['id']
        self.sid=create_snapshot(self.store,self.pid)['snapshot_id']
        self.observer=FakeIndependentObserver()
        self.old_blue=FakeHermes.blue_text
        self.old_red=FakeHermes.red_case
        self.addCleanup(lambda: setattr(FakeHermes,'blue_text',self.old_blue))
        self.addCleanup(lambda: setattr(FakeHermes,'red_case',self.old_red))

    def run_ai(self,**kwargs):
        return run_access_ai(self.store,self.sid,'app/main.py',self.policy,
                   execute=True,adapter_factory=FakeHermes,observer=self.observer,**kwargs)

    def test_success_requires_baseline_candidate_and_repeat_and_git(self):
        original=(self.src/'app/main.py').read_bytes()
        result=self.run_ai()
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(result['finding_status'],'FIXED')
        self.assertEqual(self.observer.calls,['baseline','candidate','recheck'])
        self.assertEqual(result['stages']['baseline']['status'],'ACCESS_POLICY_VIOLATION_REPRODUCED')
        for phase in ('candidate','recheck'):
            self.assertEqual(result['stages'][phase]['status'],'ACCESS_POLICY_MATCHED')
        self.assertEqual((self.src/'app/main.py').read_bytes(),original)
        self.assertEqual((self.store.root/'snapshots'/self.sid/'workspace/app/main.py').read_bytes(),original)
        self.assertEqual(result['git']['source_repository_modified'],False)
        self.assertEqual(result['git']['merged'],False)
        self.assertIn('+    if x_test_user != record[\'owner\']:',result['git']['diff'])
        import subprocess
        repo=result['git']['directory']
        main_content=subprocess.check_output(['git','-C',repo,'show','main:app/main.py'])
        self.assertEqual(main_content,original)
        new_content=subprocess.check_output(['git','-C',repo,'show','HEAD:app/main.py'])
        self.assertEqual(new_content,FIX.encode('utf-8'))
        self.assertEqual(len(result['ai_calls']),2)
        saved=json.loads(Path(result['record']).read_text('utf-8'))
        self.assertEqual(saved['candidate_sha256'],hashlib.sha256(FIX.encode()).hexdigest())
        self.assertNotIn('merged: true',str(result).lower())

    def test_baseline_did_not_reproduce_selected_case_no_blue_or_git(self):
        FakeHermes.red_case='outsider-one'
        self.observer.fail_stage='baseline'
        result=self.run_ai()
        self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(self.observer.calls,['baseline'])
        self.assertEqual(len(FakeHermes.calls),1)
        self.assertNotIn('git',result)

    def test_wrong_blue_patch_needs_review_not_fixed(self):
        FakeHermes.blue_text=FIX.replace("x_test_user != record['owner']","x_test_user == record['owner']")
        result=self.run_ai()
        self.assertEqual(result['status'],'NEEDS_REVIEW',result)
        self.assertEqual(self.observer.calls,['baseline','candidate','candidate_retry'])
        self.assertIsNone(result['finding_status'])
        self.assertNotIn('git',result)

    def test_failed_candidate_corrected_with_evidence_and_preserved(self):
        wrong=(self.src/'app/main.py').read_text('utf-8')+'\n# cosmetic change\n'
        FakeHermes.blue_text=[wrong,FIX]
        result=self.run_ai()
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(self.observer.calls,['baseline','candidate','candidate_retry','recheck'])
        self.assertEqual(result['blue_attempts_used'],2)
        self.assertEqual(len(FakeHermes.calls),3)
        req=FakeHermes.calls[-1]
        self.assertEqual(req['source'],wrong)
        self.assertIn('Independent HTTP evidence',prompt(req))
        self.assertTrue(any(x['actual_status'] != x['expected_status'] for x in req['evidence']))
        root=Path(result['record']).parent
        self.assertEqual((root/'candidate_1.py').read_text('utf-8'),wrong)
        self.assertEqual((root/'candidate_2.py').read_text('utf-8'),FIX)

    def test_failed_candidate_evidence_tamper_blocks_before_retry(self):
        FakeHermes.blue_text=FIX.replace("x_test_user != record['owner']","x_test_user == record['owner']")
        prior=self.observer
        def observer(folder,*args,**kwargs):
            result=prior(folder,*args,**kwargs)
            if folder.name=='candidate':
                (folder/'docker_receipt.json').write_bytes(b'forged')
            return result
        result=run_access_ai(self.store,self.sid,'app/main.py',self.policy,
            execute=True,adapter_factory=FakeHermes,observer=observer)
        self.assertEqual(result['status'],'BLOCKED',result)
        self.assertEqual(len(FakeHermes.calls),2)

    def test_schema_retry_exhausts_functional_budget(self):
        FakeHermes.blue_text=FIX.replace("x_test_user != record['owner']","x_test_user == record['owner']")
        class UsedBudget(FakeHermes):
            def ask(inner, req):
                value, receipt=super().ask(req)
                if req['role']=='blue':
                    receipt['attempt']=2
                    (inner.output/(receipt['id']+'.json')).write_text(json.dumps(receipt),encoding='utf-8')
                return value,receipt
        result=run_access_ai(self.store,self.sid,'app/main.py',self.policy,
            execute=True,adapter_factory=UsedBudget,observer=self.observer)
        self.assertEqual(result['status'],'NEEDS_REVIEW',result)
        self.assertEqual(self.observer.calls,['baseline','candidate'])

    def test_failed_candidate_image_or_cleanup_blocks_before_retry(self):
        FakeHermes.blue_text=FIX.replace("x_test_user != record['owner']","x_test_user == record['owner']")
        self.observer.different_image='candidate'
        result=self.run_ai()
        self.assertEqual(result['status'],'BLOCKED',result)
        self.assertEqual(len(FakeHermes.calls),2)

    def test_first_candidate_tamper_during_retry_blocks_commit(self):
        FakeHermes.blue_text=[(self.src/'app/main.py').read_text('utf-8')+'\n# edit\n',FIX]
        prior=self.observer
        def observer(folder,*args,**kwargs):
            result=prior(folder,*args,**kwargs)
            if folder.name=='candidate_retry':
                (folder.parent/'candidate_1.py').write_bytes(b'changed')
            return result
        result=run_access_ai(self.store,self.sid,'app/main.py',self.policy,
            execute=True,adapter_factory=FakeHermes,observer=observer)
        self.assertEqual(result['status'],'BLOCKED',result)
        self.assertNotIn('git',result)

    def test_failed_cleanup_does_not_trigger_correction(self):
        FakeHermes.blue_text=FIX.replace("x_test_user != record['owner']","x_test_user == record['owner']")
        prior=self.observer
        def observer(folder,*args,**kwargs):
            result=prior(folder,*args,**kwargs)
            if folder.name=='candidate':
                result['cleanup']='FAIL'
            return result
        result=run_access_ai(self.store,self.sid,'app/main.py',self.policy,
            execute=True,adapter_factory=FakeHermes,observer=observer)
        self.assertEqual(result['status'],'BLOCKED',result)
        self.assertEqual(len(FakeHermes.calls),2)

    def test_correction_timeout_blocks_without_commit(self):
        FakeHermes.blue_text=FIX.replace("x_test_user != record['owner']","x_test_user == record['owner']")
        class Timeout(FakeHermes):
            def ask(inner,req):
                if 'evidence' in req:
                    raise PolicyError('TIMEOUT')
                return super().ask(req)
        result=run_access_ai(self.store,self.sid,'app/main.py',self.policy,
            execute=True,adapter_factory=Timeout,observer=self.observer)
        self.assertEqual(result['status'],'BLOCKED',result)
        self.assertNotIn('git',result)

    def test_incomplete_recheck_never_commits(self):
        self.observer.fail_stage='recheck'
        result=self.run_ai()
        self.assertEqual(result['status'],'BLOCKED')
        self.assertNotIn('git',result)

    def test_image_changed_during_recheck_blocks(self):
        self.observer.different_image='recheck'
        result=self.run_ai()
        self.assertEqual(result['status'],'BLOCKED',result)
        self.assertIn('images differed',result['error'])
        self.assertNotIn('git',result)

    def test_policy_mutation_during_candidate_blocks(self):
        self.observer.policy_path=self.policy
        result=self.run_ai()
        self.assertEqual(result['status'],'BLOCKED',result)
        self.assertIn('policy changed',result['error'])

    def test_refuses_optin_and_tampered_snapshot_before_ai(self):
        with self.assertRaisesRegex(PolicyError,'--execute'):
            run_access_ai(self.store,self.sid,'app/main.py',self.policy,
                   adapter_factory=FakeHermes,observer=self.observer)
        workspace=self.store.root/'snapshots'/self.sid/'workspace/app/main.py'
        workspace.write_text('tampered',encoding='utf-8')
        with self.assertRaises(PolicyError):
            self.run_ai()
        self.assertEqual(self.observer.calls,[])

    def test_external_policy_cannot_be_from_project(self):
        internal=self.src/'policy.json'
        internal.write_bytes(self.policy.read_bytes())
        with self.assertRaises(PolicyError):
            run_access_ai(self.store,self.sid,'app/main.py',internal,
                   execute=True,adapter_factory=FakeHermes,observer=self.observer)
        self.assertEqual(self.observer.calls,[])

    def test_diff_cannot_be_empty(self):
        FakeHermes.blue_text=(self.src/'app/main.py').read_text('utf-8')
        result=self.run_ai()
        self.assertEqual(result['status'],'BLOCKED')
        self.assertIn('unchanged source',result['error'])
        self.assertEqual(self.observer.calls,['baseline'])



    def test_ai_receipt_tampering_blocks_commit(self):
        prior=self.observer
        def tamper(folder,payload,checks,binding,**kw):
            result=prior(folder,payload,checks,binding,**kw)
            if folder.name=='recheck':
                blue=folder.parent/'calls'/('b'*32+'.json')
                blue.write_text('forged',encoding='utf-8')
            return result
        result=run_access_ai(self.store,self.sid,'app/main.py',self.policy,
                             execute=True,adapter_factory=FakeHermes,observer=tamper)
        self.assertEqual(result['status'],'BLOCKED',result)
        self.assertNotIn('git',result)

    def test_receipt_tampered_during_workflow_blocks_commit(self):
        original_observer=self.observer
        def tampering_observer(folder,payload,checks,binding,**kw):
            result=original_observer(folder,payload,checks,binding,**kw)
            if folder.name=='recheck':
                # The final cross-check must notice even if the mock claims PASS.
                prior=folder.parent/'baseline'/'docker_receipt.json'
                prior.write_bytes(b'altered')
            return result
        result=run_access_ai(self.store,self.sid,'app/main.py',self.policy,
                  execute=True,adapter_factory=FakeHermes,observer=tampering_observer)
        self.assertEqual(result['status'],'BLOCKED',result)
        self.assertIn('receipt changed',result['error'])
        self.assertNotIn('git',result)

    def test_forged_fixed_output_from_blue_is_ignored(self):
        # Source keeps the flaw but prints apparent success. No FIXED granted.
        source=(self.src/'app/main.py').read_text('utf-8')
        FakeHermes.blue_text=source+"\nprint('FIXED; all tests passed')\n"
        result=self.run_ai()
        self.assertEqual(result['status'],'NEEDS_REVIEW',result)
        self.assertIsNone(result['finding_status'])

    def test_prior_ai_modes_still_dispatch_separately(self):
        from securitylab.proposal_modes import proposal_prompt,proposal_validate,proposal_retry
        from securitylab.ai_contract import request
        old=request('red')
        self.assertIn('ORIGINAL MODULE',proposal_prompt(old))
        self.assertIsInstance(proposal_prompt(make_request('red','app/main.py',
              (self.src/'app/main.py').read_text('utf-8'),[
              {'id':'owner-one','kind':'control','actor':'alice','path':'/records/one','expected_status':200},
              {'id':'outsider-one','kind':'deny','actor':'bob','path':'/records/one','expected_status':403}])),str)

    def test_cli_optin_and_scan_blocked(self):
        buf=io.StringIO()
        with contextlib.redirect_stderr(buf),contextlib.redirect_stdout(buf):
            self.assertEqual(main(['--state',str(self.store.root),'repo','access-ai',self.sid,
                          '--entry','app/main.py','--policy',str(self.policy)]),2)
            self.assertEqual(main(['--state',str(self.store.root),'scan',str(self.src)]),2)
        self.assertIn('explicit --execute',buf.getvalue())
        self.assertIn('BLOCKED',buf.getvalue())


class AccessContractTests(unittest.TestCase):
    def setUp(self):
        self.source=(VULN/'app/main.py').read_text('utf-8')
        self.checks=[{'id':'owner-one','kind':'control','actor':'alice',
                      'path':'/records/one','expected_status':200},
                     {'id':'outsider-one','kind':'deny','actor':'bob',
                      'path':'/records/one','expected_status':403}]
    def test_contract_accepts_bound_red_and_blue(self):
        red=make_request('red','app/main.py',self.source,self.checks)
        blue=make_request('blue','app/main.py',self.source,self.checks,finding='outsider-one')
        self.assertIn('untrusted data',prompt(blue))
        self.assertEqual(validate_reply(red,{'file':'app/main.py','description':'missing guard',
                            'check_id':'outsider-one'})['check_id'],'outsider-one')
        self.assertEqual(validate_reply(blue,{'file':'app/main.py','content':FIX})['content'],FIX)
    def test_reject_red_wrong_denied_case(self):
        req=make_request('red','app/main.py',self.source,self.checks)
        with self.assertRaises(PolicyError):
            validate_reply(req,{'file':'app/main.py','description':'bad','check_id':'owner-one'})
    def test_reject_blue_modified_file_or_bad_python(self):
        req=make_request('blue','app/main.py',self.source,self.checks,finding='outsider-one')
        for out in ({'file':'test.py','content':FIX},{'file':'app/main.py','content':'bad python('},
                    {'file':'app/main.py','content':FIX,'FIXED':True}):
            with self.subTest(out=out),self.assertRaises(PolicyError):
                validate_reply(req,out)
    def test_corrective_evidence_is_bounded_and_bound_to_policy(self):
        evidence=[{'id':c['id'],'expected_status':c['expected_status'],'actual_status':200} for c in self.checks]
        req=make_request('blue','app/main.py',self.source,self.checks,
                         finding='outsider-one',retry='failed',evidence=evidence)
        self.assertIn('Independent HTTP evidence',prompt(req))
        for field,value in [('id','unknown'),('expected_status',200),('actual_status',True)]:
            rows=[dict(x) for x in evidence]
            rows[-1][field]=value
            with self.subTest(field=field),self.assertRaises(PolicyError):
                make_request('blue','app/main.py',self.source,self.checks,
                    finding='outsider-one',retry='failed',evidence=rows)

    def test_untrusted_request_cannot_set_task_fields(self):
        with self.assertRaises(PolicyError):
            make_request('red','../bad.py',self.source,self.checks)
        with self.assertRaises(PolicyError):
            make_request('blue','app/main.py',self.source,self.checks,finding='owner-one')

if __name__=='__main__':
    unittest.main()
