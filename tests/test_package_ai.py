"""Package-contract and pipeline checks. Test doubles are not Docker/model proof."""
import contextlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
import test_access_ai as fixture
from securitylab.package_contract import make_request, validate_reply, validate_files, prompt
from securitylab.proposal_modes import proposal_retry, proposal_system
from securitylab.ai_contract import digest, MODEL_DIGEST
from securitylab.policy import PolicyError
from securitylab.storage import Store
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot
from securitylab.access_ai import run_access_ai

class PackageContractTests(unittest.TestCase):
    def request(self):
        return make_request('blue','app/main.py','x=1',[dict(id='deny',kind='deny',actor='alice',path='/one',expected_status=403)],files={'app/main.py':'x=1','app/auth.py':'y=1'},finding='deny')
    def test_only_selected_files_and_complete_sources(self):
        req=self.request()
        validate_reply(req,{'files':{'app/auth.py':'y=2'}})
        for value in [{'files':{'../other.py':'x=1'}},{'files':{'app/new.py':'x=1'}},{'file':'app/main.py','content':'x=2'},{'files':{'app/main.py':'x=1'}},{'files':{'app/main.py':'not valid python !'}}]:
            with self.subTest(value=value),self.assertRaises(PolicyError): validate_reply(req,value)
    def test_limits_and_case_collisions(self):
        for files in [{f'a{i}.py':'x=1' for i in range(9)}, {'a.py':'#'+'x'*18000}, {'A.py':'','a.py':''}]:
            with self.assertRaises(PolicyError): validate_files(files)
    def test_retry_preserves_full_context_and_schema(self):
        req=self.request();retry=proposal_retry(req,'rejected')
        self.assertEqual(retry['files'],req['files'])
        self.assertIn('files',proposal_system(req));self.assertIn('app/auth.py',prompt(retry))

class PackageHermes:
    requests=[]
    def __init__(self,cwd,output):
        self.output=Path(output);self.output.mkdir(parents=True,exist_ok=True)
    def ask(self,req):
        self.requests.append(req)
        value=({'file':'app/helper.py','description':'Possible access violation','check_id':'outsider-one'} if req['role']=='red'
               else {'files':{'app/main.py':fixture.FIX,'app/helper.py':'VALUE = 2\n'}})
        validate_reply(req,value)
        identity=('a' if req['role']=='red' else 'b')*32
        record=dict(id=identity,role=req['role'],status='PROPOSED',cleanup='PASS',attempt=1,request_sha256=digest(req),
                    response=dict(proposal=value,request_sha256=digest(req),model_digest=MODEL_DIGEST,tools=[]))
        (self.output/(identity+'.json')).write_text(json.dumps(record))
        return value,record

class PackageFlowTests(unittest.TestCase):
    def test_package_patch_and_receipts_bind_both_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/'src';shutil.copytree(fixture.VULN,src)
            (src/'app/helper.py').write_text('VALUE = 1\n')
            with contextlib.closing(Store(root/'state')) as store:
                pid=add_project(store,src)['id'];sid=create_snapshot(store,pid)['snapshot_id']
                result=run_access_ai(store,sid,'app/main.py',fixture.POLICY,execute=True,multi_file=True,
                                    adapter_factory=PackageHermes,observer=fixture.FakeIndependentObserver())
                self.assertEqual(result['status'],'PASS',result)
                self.assertEqual(result['mode'],'S9_ACCESS_AI_PACKAGE')
                self.assertEqual(result['stages']['candidate']['binding']['profile'],'access-ai-package-v1')
                self.assertEqual(result['candidates'][0]['changed_files'],['app/helper.py','app/main.py'])
                self.assertIn('app/helper.py',result['git']['diff']);self.assertIn('app/main.py',result['git']['diff'])
                folder=Path(result['record']).parent
                candidate=json.loads((folder/'candidate.json').read_text())
                self.assertEqual(candidate['app/helper.py'],'VALUE = 2\n')
                self.assertEqual((src/'app/helper.py').read_text(),'VALUE = 1\n')
                self.assertEqual(result['stages']['candidate']['binding']['payload_sha256'],result['stages']['recheck']['binding']['payload_sha256'])

if __name__=='__main__':unittest.main()

import test_dashboard as dashboard_fixture
import time
class PackageDashboardTests(unittest.TestCase):
    setUp=dashboard_fixture.DashboardTests.setUp
    def test_package_profile_reaches_worker_and_old_grant_cannot_be_reused(self):
        cfg=self.app.profiles.get('default')
        old=json.dumps(self.inp,sort_keys=True)
        self.app.grants[old]=(time.monotonic(),cfg.sha256)
        self.inp['profileId']='access-ai-package-v1'
        with self.assertRaises(PolicyError): self.app.launch(self.inp)
        received=[]
        def runner(*args,**kw):
            received.append(kw.get('multi_file'));return {'status':'BLOCKED','error':'synthetic stop'}
        self.app.runner=runner
        self.app.grants[json.dumps(self.inp,sort_keys=True)]=(time.monotonic(),cfg.sha256)
        run=self.app.launch(self.inp)
        for _ in range(100):
            if self.app.active is None:break
            time.sleep(.01)
        self.assertEqual(received,[True])
        self.assertEqual(self.app.run(run['runId'])['profileId'],'access-ai-package-v1')
    def test_large_package_rejected_before_launch(self):
        for i in range(9):(self.src/f'x{i}.py').write_text('x=1')
        with contextlib.closing(Store(self.app.root)) as store:
            self.inp['snapshotId']=create_snapshot(store,self.inp['projectId'])['snapshot_id']
        self.inp['profileId']='access-ai-package-v1'
        with self.assertRaises(PolicyError):self.app.validate_input(self.inp)
