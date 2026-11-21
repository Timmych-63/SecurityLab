import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from securitylab.ai_contract import request, prompt, strict_json, validate_proposal, digest, HERMES_REVISION, MODEL, MODEL_DIGEST
from securitylab.fixture import FIXED, VULNERABLE
from securitylab.hermes_adapter import validate_envelope
from securitylab.hermes_worker import invoke
from securitylab.ai_workflow import run_ai
from securitylab.policy import PolicyError
from securitylab.storage import Store
RED={'file':'service.py','description':'Missing ownership check','user':'alice','record_id':'two'}
BLUE={'file':'service.py','content':FIXED}
def envelope(req,value):
    return dict(schema_version=1,role=req['role'],request_sha256=digest(req),hermes_revision=HERMES_REVISION,model=MODEL,model_digest=MODEL_DIGEST,tools=[],proposal=value)
class ContractTests(unittest.TestCase):
    def test_valid(self):
        validate_proposal('red',RED);validate_proposal('blue',BLUE)
    def test_formatting(self):
        validate_proposal('blue',dict(BLUE,content='# comment\n'+FIXED.replace('"',"'")))
    def test_unsafe_code(self):
        for source in [VULNERABLE,FIXED+'\nimport os\n',FIXED.replace('403','200'),FIXED.replace('alice','mallory')]:
            with self.subTest(source=source),self.assertRaises(PolicyError):validate_proposal('blue',dict(BLUE,content=source))
    def test_paths_and_success_claims(self):
        for value in [dict(BLUE,file='../service.py'),dict(BLUE,status='FIXED'),{'status':'FIXED'}]:
            with self.assertRaises(PolicyError):validate_proposal('blue',value)
    def test_strict_json(self):
        for text in ['{"a":1,"a":2}','{} trailing','[]','X'*33000]:
            with self.assertRaises(PolicyError):strict_json(text)
        self.assertEqual(strict_json('```json\n{"ready":true}\n```'),{'ready':True})
    def test_wrong_finding(self):
        with self.assertRaises(PolicyError):validate_proposal('red',dict(RED,record_id='one'))
    def test_request(self):
        self.assertNotIn('record[\\"owner\\"] != user',prompt(request('blue',RED)))
        with self.assertRaises(PolicyError):prompt(dict(request('red'),source='x'))
    def test_bindings(self):
        req=request('red');value=envelope(req,RED)
        self.assertEqual(validate_envelope(req,value),RED)
        for key,bad in [('role','blue'),('request_sha256','0'*64),('tools',['terminal']),('model','other'),('schema_version',True),('model_digest','bad')]:
            with self.subTest(key=key),self.assertRaises(PolicyError):validate_envelope(req,dict(value,**{key:bad}))
    def test_boolean(self):
        req=request('smoke')
        with self.assertRaises(PolicyError):validate_envelope(req,envelope(req,{'ready':1}))
class Agent:
    instances=[];tool_list=[];messages=[];reply='{"ready":true}'
    def __init__(self,**kwargs):self.kwargs=kwargs;self.tools=self.tool_list;self.instances.append(self)
    def run_conversation(self,**kwargs):return {'final_response':self.reply,'messages':self.messages}
class WorkerTests(unittest.TestCase):
    def setUp(self):Agent.instances=[];Agent.tool_list=[];Agent.messages=[];Agent.reply='{"ready":true}'
    def test_fresh_no_tools(self):
        invoke(request('smoke'),Agent);invoke(request('smoke'),Agent)
        self.assertEqual(len(Agent.instances),2)
        self.assertEqual(Agent.instances[0].kwargs['enabled_toolsets'],[])
        self.assertTrue(Agent.instances[0].kwargs['skip_memory'])
        with self.assertRaises(PolicyError):Agent.instances[0]._execute_tool_calls(None)
    def test_tools_fail_closed(self):
        Agent.tool_list=['terminal']
        with self.assertRaises(PolicyError):invoke(request('smoke'),Agent)
    def test_tool_message(self):
        Agent.messages=[{'role':'tool'}]
        with self.assertRaises(PolicyError):invoke(request('smoke'),Agent)
    def test_invalid_answer(self):
        Agent.reply='FIXED'
        with self.assertRaises(PolicyError):invoke(request('smoke'),Agent)
class Adapter:
    calls=[];bad=False
    def __init__(self,*args):pass
    def ask(self,req):
        self.calls.append(req['role'])
        value={'ready':True} if req['role']=='smoke' else dict(RED if req['role']=='red' else BLUE)
        if self.bad and req['role']=='blue':value['content']=VULNERABLE
        return value,{'id':req['role'],'response':envelope(req,value)}
class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name)/'state');Adapter.calls=[];Adapter.bad=False
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def test_smoke_not_fixed(self):
        result=run_ai(self.store,True,Adapter)
        self.assertEqual(result['status'],'PASS',result);self.assertIsNone(result['finding_status']);self.assertEqual(self.store.runs(),[])
    def test_rejected_patch_not_executed(self):
        Adapter.bad=True;result=run_ai(self.store,False,Adapter)
        self.assertEqual(result['status'],'BLOCKED');self.assertEqual(self.store.runs(),[])
    def test_failure_no_fallback(self):
        def unavailable(*args):raise PolicyError('not installed')
        result=run_ai(self.store,False,unavailable)
        self.assertEqual(result['status'],'BLOCKED');self.assertEqual(self.store.runs(),[]);self.assertTrue(Path(result['record']).exists())
    def test_full_workflow(self):
        from test_docker_workflow import FixtureBroker
        from securitylab.orchestrator import Orchestrator
        result=run_ai(self.store,False,Adapter,lambda s:Orchestrator(s,docker_broker_factory=FixtureBroker))
        self.assertEqual(result['status'],'PASS',result);self.assertEqual(Adapter.calls,['red','blue']);self.assertEqual(result['finding_status'],'FIXED')
        self.assertEqual(self.store.get(result['verification_run'])['mode'],'scripted-demo-docker-no-ai')
    def test_owner_variable_workflow_reports_canonicalization(self):
        from securitylab.ai_contract import REVIEWED_FIXES
        from test_docker_workflow import FixtureBroker
        from securitylab.orchestrator import Orchestrator
        class OwnerAdapter(Adapter):
            def ask(self, req):
                value, call = super().ask(req)
                if req['role'] == 'blue':
                    value['content'] = REVIEWED_FIXES['local-owner-user-first']
                    call['response'] = envelope(req, value)
                return value, call
        result = run_ai(self.store, False, OwnerAdapter,
                        lambda s: Orchestrator(s, docker_broker_factory=FixtureBroker))
        self.assertEqual(result['status'], 'PASS', result)
        self.assertEqual(result['reviewed_variant'], 'local-owner-user-first')
        self.assertIn('original proposal not executed', result['canonicalization'])
        self.assertIn('owner = record', result['blue']['content'])

from securitylab.process import Result
from securitylab.hermes_adapter import HermesAdapter
class DockerTransport:
    def __init__(self, bad=None):self.bad=bad;self.calls=[]
    def __call__(self,argv,cwd,limits,**kwargs):
        self.calls.append(argv)
        out='';code=0;timed=False
        args=argv[3:] if '--host' in argv else argv[1:]
        if args[:2]==['context','inspect']:out='unix:///var/run/docker.sock'
        elif args[:2]==['image','inspect']:out=json.dumps([{'Id':'sha256:'+'a'*64,'Config':{}}])
        elif args[:2]==['network','inspect']:out=json.dumps([{'Internal':self.bad!='network','Driver':'bridge'}])
        elif args[0]=='inspect' and '--format' not in args:
            out=json.dumps([{'Config':{'Image':'sha256:'+'a'*64,'User':'10001:10001'},'HostConfig':{
                'ReadonlyRootfs':True,'Privileged':self.bad=='privileged','NetworkMode':'securitylab-ai-private',
                'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],'Memory':1610612736,'MemorySwap':1610612736,
                'PidsLimit':128,'NanoCpus':1000000000,'Tmpfs':{'/tmp':'rw'}},'Mounts':[]}])
        elif args[0]=='inspect':out=json.dumps({'Running':False,'OOMKilled':self.bad=='oom','ExitCode':0,'Error':''})
        elif args[0]=='start':
            req=json.loads(kwargs['input_data']);out=json.dumps(envelope(req,{'ready':True}));timed=self.bad=='timeout'
            if self.bad=='claim':out='FIXED'
        elif args[0]=='ps' and self.bad=='cleanup':out='container-still-here'
        return Result(argv,code,out,'',timed,False,False,0.01)
class TransportTests(unittest.TestCase):
    def test_roundtrip_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            fake=DockerTransport();adapter=HermesAdapter(Path(directory),Path(directory)/'calls',fake)
            value,record=adapter.ask(request('smoke'))
            self.assertEqual(value,{'ready':True});self.assertEqual(record['cleanup'],'PASS')
            self.assertTrue(any('rm' in x for x in fake.calls))
    def test_failures_never_produce_proposal(self):
        for bad in ['network','privileged','oom','timeout','claim','cleanup']:
            with self.subTest(bad=bad),tempfile.TemporaryDirectory() as directory:
                fake=DockerTransport(bad)
                with self.assertRaises(PolicyError):HermesAdapter(Path(directory),Path(directory)/'calls',fake).ask(request('smoke'))
                if bad!='network':self.assertTrue(any('rm' in x for x in fake.calls))
                if bad=='privileged':self.assertFalse(any('start' in x for x in fake.calls))

class RedRegressionTests(unittest.TestCase):
    def test_unknown_caller_cross_owner_is_valid(self):
        validate_proposal('red', dict(RED, user='mallory'))
    def test_invalid_cases_are_denied(self):
        for user, record_id in [('bob','two'), (None,'two'), ('alice','missing'), ('caller','record'), ([], 'two'), ('', 'two')]:
            with self.subTest(user=user,record_id=record_id), self.assertRaises(PolicyError):
                validate_proposal('red', dict(RED,user=user,record_id=record_id))
    def test_rejected_raw_response_captured_before_validation(self):
        class InvalidAgent(Agent):
            tool_list=[]; messages=[]
            reply=json.dumps(dict(RED,user='bob'))
        captured=[]
        with self.assertRaises(PolicyError):invoke(request('red'),InvalidAgent,captured.append)
        self.assertEqual(captured,[InvalidAgent.reply])
    def test_malformed_reply_is_also_captured(self):
        class InvalidAgent(Agent):
            tool_list=[]; messages=[]; reply='not JSON'
        captured=[]
        with self.assertRaises(PolicyError):invoke(request('red'),InvalidAgent,captured.append)
        self.assertEqual(captured,['not JSON'])

class BlueAttemptTransport(DockerTransport):
    def __init__(self, always_reject=False, bad=None):
        super().__init__(bad);self.starts=0;self.always_reject=always_reject;self.limits=[]
    def __call__(self,argv,cwd,limits,**kwargs):
        r=super().__call__(argv,cwd,limits,**kwargs)
        args=argv[3:] if '--host' in argv else argv[1:]
        if args[0]=='start':
            self.starts+=1;self.limits.append(limits.timeout)
            req=json.loads(kwargs['input_data'])
            if self.starts==1 or self.always_reject:
                r.returncode=2;r.stdout=''
                raw=json.dumps(dict(BLUE,content='def read_record(user, record_id): pass'))
                r.stderr='AI_RESPONSE_JSON='+json.dumps(raw)+'\nAI_ATTEMPT_JSON='+json.dumps({'role':'blue','attempt':self.starts,'status':'REJECTED'})
            else:r.stdout=json.dumps(envelope(req,BLUE))
        if args[0]=='inspect' and '--format' in args:
            state=json.loads(r.stdout);state['ExitCode']=2 if self.starts==1 or self.always_reject else 0;r.stdout=json.dumps(state)
        return r

class IndependentAttemptTests(unittest.TestCase):
    def test_two_containers_independent_budgets_and_receipts(self):
        with tempfile.TemporaryDirectory() as d:
            fake=BlueAttemptTransport();a=HermesAdapter(Path(d),Path(d)/'calls',fake)
            value,record=a.ask(request('blue',RED))
            self.assertEqual(value,BLUE);self.assertEqual(fake.limits,[1200,1200]);self.assertEqual(record['attempt'],2)
            records=[json.loads(p.read_text()) for p in (Path(d)/'calls').glob('*.json')]
            self.assertEqual(len(records),2);self.assertEqual({r['status'] for r in records},{'REJECTED','PROPOSED'})
            self.assertTrue(all(r['cleanup']=='PASS' for r in records))
            creates=[i for i,c in enumerate(fake.calls) if 'create' in c];removes=[i for i,c in enumerate(fake.calls) if 'rm' in c]
            self.assertLess(removes[0],creates[1])
    def test_stop_after_two_rejections(self):
        with tempfile.TemporaryDirectory() as d:
            fake=BlueAttemptTransport(always_reject=True)
            with self.assertRaises(PolicyError):HermesAdapter(Path(d),Path(d)/'calls',fake).ask(request('blue',RED))
            self.assertEqual(fake.starts,2)
    def test_cleanup_failure_does_not_retry(self):
        with tempfile.TemporaryDirectory() as d:
            fake=BlueAttemptTransport(bad='cleanup')
            with self.assertRaises(PolicyError):HermesAdapter(Path(d),Path(d)/'calls',fake).ask(request('blue',RED))
            self.assertEqual(fake.starts,1)
    def test_timeout_status_and_no_retry(self):
        with tempfile.TemporaryDirectory() as d:
            fake=BlueAttemptTransport(bad='timeout')
            with self.assertRaisesRegex(PolicyError,'TIMEOUT'):HermesAdapter(Path(d),Path(d)/'calls',fake).ask(request('blue',RED))
            self.assertEqual(fake.starts,1)
            record=json.loads(next((Path(d)/'calls').glob('*.json')).read_text())
            self.assertEqual(record['status'],'TIMEOUT');self.assertEqual(record['cleanup'],'PASS')
    def test_retry_request_bounds_and_feedback(self):
        retry=request('blue',RED,json.dumps(dict(BLUE,content='def read_record(user, record_id): pass')))
        self.assertIn('RECORDS assignment',prompt(retry))
        with self.assertRaises(PolicyError):request('red',retry='anything')
        with self.assertRaises(PolicyError):request('blue',RED,'x'*16001)
    def test_worker_one_attempt_system_schema(self):
        class OneAgent(Agent):
            reply=json.dumps(BLUE);tool_list=[];messages=[];instances=[]
            def run_conversation(self,**kwargs):
                self.conversation=kwargs;return super().run_conversation(**kwargs)
        self.assertEqual(invoke(request('blue',RED),OneAgent),BLUE)
        self.assertEqual(len(OneAgent.instances),1)
        a=OneAgent.instances[0]
        self.assertIn('Allowed keys: file, content',a.conversation['system_message'])
        self.assertEqual(a.kwargs['request_overrides']['response_format'],{'type':'json_object'})

class TransportRejectionTests(unittest.TestCase):
    """Live run #1: truncated/degenerate replies must become corrective attempts."""
    def _invoke(self,agent):
        err=io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(PolicyError) as ctx:
                invoke(request('red'),agent)
        return err.getvalue(),str(ctx.exception)
    def test_truncated_reply_becomes_rejected_attempt_with_feedback(self):
        class TruncatedAgent(Agent):
            tool_list=[];messages=[]
            def run_conversation(self,**kwargs):
                return {'error':"\u26a0\ufe0f Response truncated (finish_reason='length') - model hit max output tokens",
                        'messages':[]}
        captured=[]
        err=io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(PolicyError) as ctx:
                invoke(request('red'),TruncatedAgent,captured.append)
        self.assertEqual(captured,[])  # garbage is not passed off as a proposal
        self.assertIn('Hermes conversation failed: response truncated',str(ctx.exception))
        lines=err.getvalue().splitlines()
        raw=[l for l in lines if l.startswith('AI_RESPONSE_JSON=')]
        attempt=[l for l in lines if l.startswith('AI_ATTEMPT_JSON=')]
        self.assertEqual(len(raw),1);self.assertEqual(len(attempt),1)
        feedback=json.loads(raw[0][len('AI_RESPONSE_JSON='):])
        decision=json.loads(attempt[0][len('AI_ATTEMPT_JSON='):])
        self.assertEqual(decision['status'],'REJECTED');self.assertEqual(decision['attempt'],1)
        self.assertEqual(decision['role'],'red');self.assertIn('truncated',decision['reason'])
        self.assertTrue(isinstance(feedback,str) and 0<len(feedback.encode())<=4000)
    def test_degenerate_repetition_is_classified(self):
        class DegenerateAgent(Agent):
            tool_list=[];messages=[]
            def run_conversation(self,**kwargs):
                return {'error':'\U0001f501 Response dominated by repeated text - stopping instead of continuing a degenerate response.','messages':[]}
        err,error_text=self._invoke(DegenerateAgent)
        self.assertIn('response degenerated into repeated text',error_text)
        self.assertIn('AI_ATTEMPT_JSON=',err)
    def test_empty_reply_is_also_recoverable(self):
        class EmptyAgent(Agent):
            tool_list=[];messages=[]
            def run_conversation(self,**kwargs):
                return {'final_response':None,'messages':[]}
        err,error_text=self._invoke(EmptyAgent)
        self.assertIn('Hermes conversation failed',error_text)
        self.assertIn('AI_ATTEMPT_JSON=',err)
    def test_worker_failure_keeps_normal_rejection_path(self):
        # A real validator rejection in S7.2 still prints the raw response, not
        # feedback; research tasks instead add a bounded note (see below).
        class InvalidAgent(Agent):
            tool_list=[];messages=[];reply='not JSON'
        captured=[]
        err=io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(PolicyError):
                invoke(request('red'),InvalidAgent,captured.append)
        self.assertEqual(captured,['not JSON'])

class ResearchContractRejectionTests(unittest.TestCase):
    """Live run #3: a research contract rejection fed the raw response (up to
    16000 bytes) into the 4000-byte retry field and stopped the run with
    'Invalid research corrective feedback'. The worker must compose bounded
    corrective feedback for research tasks instead."""
    @classmethod
    def setUpClass(cls):
        from securitylab.research_contract import make_request
        mapping={'entry':'app/main.py','files':['app/main.py'],
                 'routes':[{'method':'GET','path':'/records/one','file':'app/main.py'}],
                 'dependencies':['fastapi']}
        cls.req=make_request('app/main.py',mapping,
                             '# Документация\nПриложение отдаёт записи.',
                             [],{'decisions_left':12,'requests_left':40,'seconds_left':600},['alice','bob'])
    def _invoke(self,reply):
        class InvalidAgent(Agent):
            tool_list=[];messages=[]
        InvalidAgent.reply=reply
        captured=[]
        err=io.StringIO()
        def capture(raw):  # mirror the real worker wiring: main() prints the raw reply
            captured.append(raw)
            print('AI_RESPONSE_JSON='+json.dumps(raw,ensure_ascii=True),file=sys.stderr)
        with contextlib.redirect_stderr(err):
            with self.assertRaises(PolicyError):
                invoke(self.req,InvalidAgent,capture)
        return err.getvalue(),captured
    def _note(self,stderr):
        raw=[l for l in stderr.splitlines() if l.startswith('AI_RESPONSE_JSON=')]
        self.assertGreaterEqual(len(raw),2)  # raw receipt capture plus composed note
        return json.loads(raw[-1][len('AI_RESPONSE_JSON='):])
    def test_big_invalid_reply_gets_bounded_feedback(self):
        stderr,captured=self._invoke('x'*8000)
        self.assertEqual(captured,['x'*8000])  # receipt keeps the raw response
        note=self._note(stderr)
        self.assertIn('exactly one compact valid JSON',note)
        self.assertLessEqual(len(note.encode()),4000)
    def test_validation_failure_reason_reaches_feedback(self):
        bad=json.dumps({'action':'read','file':'app/main.py','start':1,'count':10,'extra':'y'*6000})
        stderr,captured=self._invoke(bad)
        note=self._note(stderr)
        self.assertIn('read requires',note)
        self.assertLessEqual(len(note.encode()),4000)
    def test_rejection_seam_builds_valid_research_retry(self):
        from securitylab.hermes_adapter import rejected_reply
        from securitylab.research_contract import prompt as research_prompt
        from securitylab.research_contract import retry_request
        stderr,_=self._invoke(json.dumps({'action':'read','file':'app/main.py','start':1,'count':10,'extra':'y'*6000}))
        previous,reason,proposal=rejected_reply(stderr,'red',1)
        self.assertIn('exactly one compact valid JSON',previous)
        self.assertEqual(proposal.get('action'),'read')  # rejected proposal surfaces for the auto-probe
        retry=retry_request(self.req,previous)
        self.assertIn('CORRECTIVE ATTEMPT',research_prompt(retry))
    def test_blue_contract_rejection_also_bounded(self):
        from securitylab.hermes_adapter import rejected_reply
        from securitylab.research_contract import blue_prompt, make_blue_request, retry_request
        blue=make_blue_request('app/main.py',{'app/main.py':'x = 1\n'},
                               [{'id':'deny-1','file':'app/main.py','path':'/records/one','actor':'bob',
                                 'expected_status':403,'observed_status':200,
                                 'description':'foreign read','basis':'documentation'}],
                               '# Документация\nЗаписи может читать только владелец.',
                               [{'path':'/records/one','actor':'bob','actual_status':200}])
        class BadBlueAgent(Agent):
            tool_list=[];messages=[]
        BadBlueAgent.reply=json.dumps({'files':{'app/main.py':'x = 2\n','app/other.py':'z = 1\n'}})
        err=io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(PolicyError):
                invoke(blue,BadBlueAgent)
        previous,reason,proposal=rejected_reply(err.getvalue(),'blue',1)
        self.assertEqual(proposal,{'files':{'app/main.py':'x = 2\n','app/other.py':'z = 1\n'}})
        retry=retry_request(blue,previous)
        self.assertIn('CORRECTIVE ATTEMPT',blue_prompt(retry))
    def test_http_schema_rejection_feedback_shows_canonical_shape(self):
        # Live run #5: checks carrying extra keys (method copied from the ROUTES
        # dump) were rejected twice under a generic note; the corrective note
        # must repeat the reason and the exact check shape instead.
        bad=json.dumps({'action':'http','checks':[{'path':'/records/one','actor':'bob','method':'GET'}]})
        stderr,captured=self._invoke(bad)
        note=self._note(stderr)
        self.assertIn('Each http check needs exactly',note)
        self.assertIn('"checks":[{"path":"/records/one","actor":null}]',note)
        self.assertLessEqual(len(note.encode('utf-8')),2000)
        from securitylab.research_contract import prompt as research_prompt, retry_request
        retry=retry_request(self.req,note)
        self.assertIn('CORRECTIVE ATTEMPT',research_prompt(retry))

class ResearchAttemptTransport(DockerTransport):
    """First starts die with the transport-level REJECTED reply seen in the live run."""
    def __init__(self,fail_times=1):
        super().__init__();self.starts=0;self.fail_times=fail_times;self.requests=[]
        self.feedback=('Your previous response was rejected: response truncated: model hit '
                       'the output token limit. Reply again with exactly one compact valid '
                       'JSON object exactly as prescribed by the schema.')
    def __call__(self,argv,cwd,limits,**kwargs):
        r=super().__call__(argv,cwd,limits,**kwargs)
        args=argv[3:] if '--host' in argv else argv[1:]
        if args[0]=='start':
            self.starts+=1
            req=json.loads(kwargs['input_data']);self.requests.append(req)
            if self.starts<=self.fail_times:
                r.returncode=2;r.stdout=''
                r.stderr=('AI_RESPONSE_JSON='+json.dumps(self.feedback)+'\nAI_ATTEMPT_JSON='+
                          json.dumps({'role':'red','attempt':self.starts,'status':'REJECTED',
                                      'reason':"\u26a0\ufe0f Response truncated (finish_reason='length') - model hit max output tokens"}))
            else:
                r.stdout=json.dumps(envelope(req,{'action':'read','file':'app/main.py','start':1,'count':10}))
        if args[0]=='inspect' and '--format' in args:
            state=json.loads(r.stdout);state['ExitCode']=2 if self.starts<=self.fail_times else 0;r.stdout=json.dumps(state)
        return r
class ResearchTransportRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from securitylab.research_contract import make_request
        mapping={'entry':'app/main.py','files':['app/main.py'],
                 'routes':[{'method':'GET','path':'/records/one','file':'app/main.py'}],
                 'dependencies':['fastapi']}
        cls.req=make_request('app/main.py',mapping,
                             '# \u0414\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u0446\u0438\u044f\n\u041f\u0440\u0438\u043b\u043e\u0436\u0435\u043d\u0438\u0435 \u043e\u0442\u0434\u0430\u0451\u0442 \u0437\u0430\u043f\u0438\u0441\u0438.',
                             [],{'decisions_left':12,'requests_left':40,'seconds_left':600},['alice','bob'])
    def test_truncated_attempt_retries_with_feedback_then_continues(self):
        with tempfile.TemporaryDirectory() as d:
            fake=ResearchAttemptTransport(fail_times=1)
            value,record=HermesAdapter(Path(d),Path(d)/'calls',fake).ask(self.req)
            self.assertEqual(value,{'action':'read','file':'app/main.py','start':1,'count':10})
            self.assertEqual(record['attempt'],2);self.assertEqual(fake.starts,2)
            self.assertEqual(fake.requests[1].get('retry'),fake.feedback)
            records=[json.loads(p.read_text()) for p in (Path(d)/'calls').glob('*.json')]
            self.assertEqual({r['status'] for r in records},{'REJECTED','PROPOSED'})
            rejected=[r for r in records if r['status']=='REJECTED'][0]
            self.assertIn('truncated',rejected['error']);self.assertEqual(rejected['cleanup'],'PASS')
    def test_second_truncated_attempt_stops_with_reason(self):
        with tempfile.TemporaryDirectory() as d:
            fake=ResearchAttemptTransport(fail_times=2)
            with self.assertRaises(PolicyError) as ctx:
                HermesAdapter(Path(d),Path(d)/'calls',fake).ask(self.req)
            self.assertEqual(fake.starts,2)
            self.assertIn('truncated',str(ctx.exception))
            self.assertIn('call receipt',str(ctx.exception))
