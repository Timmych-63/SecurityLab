"""S6.3b local unit tests. Docker is simulated, not live integration."""
import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import tempfile
import unittest

from securitylab.cli import main
from securitylab.container_runner import IMAGE_ID
from securitylab.http_probe import http_probe_snapshot, validate_checks
from securitylab.http_runner import HTTPDockerBroker, ServiceAttachment, VERIFIER_SCRIPT, http_create_args
from securitylab.policy import PolicyError
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot
from securitylab.storage import Store
from test_container_runner import response, IMAGE


class FakeHTTPDocker:
    def __init__(self):
        self.calls = []
        self.endpoint = 'npipe:////./pipe/dockerDesktopLinuxEngine'
        self.network = None
        self.containers = {}
        self.verifier_problem = None
        self.status_override = None
        self.unsafe_network = False
        self.unsafe_container = False
        self.cleanup_failure = False
        self.target_stdout = 'FIXED: all tests passed' # ignored
        self.results = None

    def __call__(self, argv, cwd, limits, **kwargs):
        args = argv[3:] if argv[1:2] == ['--host'] else argv[1:]
        self.calls.append((args, kwargs))
        if args[:2] == ['context','inspect']:
            return response(self.endpoint)
        if args[:2] == ['image','inspect']:
            return response(json.dumps([{'Id':IMAGE,'Config':{'Volumes':None}}]))
        if args[:2] == ['network','create']:
            self.network = args[-1]
            return response('n'*64)
        if args[:2] == ['network','inspect']:
            return response(json.dumps([{'Name':self.network,'Internal':not self.unsafe_network,
                'Driver':'bridge','Attachable':False,'Ingress':False,'Containers':{}}]))
        if args[:2] == ['network','rm']:
            return response(code=1 if self.cleanup_failure else 0)
        if args[:2] == ['network','ls']:
            return response(self.network if self.cleanup_failure else '')
        if args[0] == 'create':
            name = args[args.index('--name')+1]
            self.containers[name] = args
            return response('c'*64)
        if args[0] == 'inspect' and '--format' not in args:
            name=args[1]
            opts=self.containers[name]
            unsafe=[{'Type':'bind'}] if self.unsafe_container else []
            return response(json.dumps([{'Config':{'Image':IMAGE,'User':'10001:10001','ExposedPorts':None},
                'HostConfig':{'Privileged':False,'NetworkMode':self.network,
                              'ReadonlyRootfs':True,'Binds':None,'PortBindings':None,
                              'PidMode':'','IpcMode':'private','CapDrop':['ALL'],
                              'SecurityOpt':['no-new-privileges:true'],'Memory':536870912,
                              'MemorySwap':536870912,'NanoCpus':1000000000,'PidsLimit':64,
                              'Devices':None,'DeviceRequests':None,
                              'Tmpfs':{'/tmp':'opts','/work':'opts'}},
                'Mounts':unsafe,'NetworkSettings':{'Networks':{self.network:{}}}}]))
        if args[:2] == ['start','--attach']:
            verifier_name=args[2]
            command=self.containers[verifier_name]
            env=command[command.index('--env')+1].split('=',1)[1]
            contract=json.loads(base64.b64decode(env).decode())
            checks=contract['checks']
            if self.verifier_problem == 'bad-nonce':
                nonce='WRONG'
            else:
                nonce=contract['nonce']
            obs=[]
            for check in checks:
                actual=(None if self.verifier_problem=='unreachable' else
                        self.status_override if self.status_override is not None else check['expected_status'])
                obs.append({'path':check['path'],'expected_status':check['expected_status'],
                            'actual_status':actual,'passed':actual==check['expected_status'],
                            'error':'ConnectionRefusedError' if actual is None else None})
            if self.verifier_problem == 'self-contradiction':
                obs[0]['passed'] = not obs[0]['passed']
            result={'schema_version':1,'nonce':nonce,'observations':obs}
            self.results=result
            code=0 if all(row['passed'] for row in obs) else 1
            if self.verifier_problem == 'exit-mismatch':
                code=1-code
            if self.verifier_problem == 'timeout':
                return response('partial',code=-9,timed_out=True)
            if self.verifier_problem == 'garbage':
                return response('FIXED!\n',code=0)
            return response(json.dumps(result),code=code)
        if args[:2] == ['inspect','--format']:
            name=args[-1]
            is_target='--network-alias' in self.containers[name]
            if is_target:
                return response(json.dumps({'Running':True,'ExitCode':0,'OOMKilled':False,'Error':''}))
            code=0 if all(x['passed'] for x in (self.results or {}).get('observations',[])) else 1
            if self.verifier_problem == 'exit-mismatch':
                code=1-code
            return response(json.dumps({'Running':False,'ExitCode':code,'OOMKilled':False,'Error':''}))
        if args[:2] == ['rm','--force']:
            return response('deleted')
        if args[:2] == ['ps','--all']:
            return response('')
        raise AssertionError('Unhandled fake docker args: '+str(args))

class FakeAttachment:
    inputs=[]
    def __init__(self, cmd, cwd, payload):
        self.__class__.inputs.append((cmd, payload))
    def healthy_transport(self):
        pass
    def close(self):
        pass

class ParseTests(unittest.TestCase):
    def test_checks_accept_multiple_paths_and_expected_codes(self):
        self.assertEqual(validate_checks(['/health=200','/v1/items?page=2=204','/bad=404']),
                         [{'path':'/health','expected_status':200},
                          {'path':'/v1/items?page=2','expected_status':204},
                          {'path':'/bad','expected_status':404}])
    def test_checks_reject_unsafe_values(self):
        invalid=[[],['/health'],['http://127.0.0.1:80=200'],['//some=200'],
                 ['/../admin=200'],['/abc%0d%0aHost=200','/hi=201'],['/a=abc'],
                 ['/a=199'],['/a=600'],['/a=200','/a=201'],['/bad\n=200'],
                 ['/x=200']*9, ['/a#frag=200']]
        for value in invalid:
            with self.subTest(value=value),self.assertRaises(PolicyError):
                validate_checks(value)
    def test_fixed_verifier_has_valid_python_syntax(self):
        compile(VERIFIER_SCRIPT,'<trusted-http-verifier>','exec')
        self.assertIn("HTTPConnection('target',8000",VERIFIER_SCRIPT)
        self.assertNotIn('subprocess',VERIFIER_SCRIPT)
    def test_docker_args_pin_image_and_no_host_ports(self):
        net='securitylab-http-'+'a'*32
        name='securitylab-job-'+'b'*32
        for target in (True,False):
            args=http_create_args(IMAGE,name,net,target=target,contract_b64=None if target else 'e30=')
            self.assertEqual(args[args.index('--network')+1],net)
            for denied in ('--publish','--mount','--volume','--privileged','--network=host'):
                self.assertNotIn(denied,args)
            self.assertIn('--read-only',args)
            self.assertIn('--cap-drop',args)
            self.assertEqual('--network-alias' in args,target)
            if target:
                self.assertNotIn('--env',args)
            else:
                self.assertIn(VERIFIER_SCRIPT,args)
        with self.assertRaises(PolicyError):
            http_create_args(IMAGE,name,'bridge',target=True)
        with self.assertRaises(PolicyError):
            http_create_args('python:latest',name,net,target=True)

class LocalTransportContractTests(unittest.TestCase):
    """Trusted verifier and pipe transport only; NOT an actual Docker run."""
    def test_host_subprocess_pipe_simulation_only(self):
        payload=b'{"hello":"world"}'
        code='import sys;print(len(sys.stdin.buffer.read()),flush=True)'
        with tempfile.TemporaryDirectory() as tmp:
            attachment=ServiceAttachment([sys.executable,'-u','-c',code],Path(tmp),payload)
            try:
                attachment.process.wait(timeout=5)
                attachment.healthy_transport()
                self.assertIn(str(len(payload)).encode(),attachment.buffers[0])
            finally:
                attachment.close()

    def test_trusted_verifier_against_synthetic_local_http_server(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200 if self.path=='/up' else 404)
                self.send_header('Content-Length','0')
                self.end_headers()
            def log_message(self, *_):
                pass
        try:
            server=HTTPServer(('127.0.0.1',0),Handler)
        except OSError:
            self.skipTest('Local loopback bind unavailable')
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            port=server.server_address[1]
            script=VERIFIER_SCRIPT.replace("HTTPConnection('target',8000",f"HTTPConnection('127.0.0.1',{port}")
            config={'nonce':'fixed-nonce','checks':[{'path':'/up','expected_status':200},
                                                   {'path':'/missing','expected_status':404}]}
            environment=dict(os.environ)
            environment['SL_HTTP_CONTRACT']=base64.b64encode(json.dumps(config).encode()).decode()
            r=subprocess.run([sys.executable,'-I','-B','-c',script],env=environment,
                             cwd=tempfile.gettempdir(),text=True,capture_output=True,timeout=10)
            self.assertEqual(r.returncode,0,r.stderr)
            doc=json.loads(r.stdout)
            self.assertEqual(doc['nonce'],'fixed-nonce')
            self.assertTrue(all(row['passed'] for row in doc['observations']))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

class HTTPFlowTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.project=self.root/'python-api';self.project.mkdir()
        (self.project/'main.py').write_text('from http.server import HTTPServer\n',encoding='utf-8')
        (self.project/'pyproject.toml').write_text('[project]\nname="a"\nversion="0.1"\n',encoding='utf-8')
        self.store=Store(self.root/'state');self.addCleanup(self.store.close)
        pid=add_project(self.store,self.project,'HTTP sample')['id']
        self.snapshot=create_snapshot(self.store,pid)
        self.sid=self.snapshot['snapshot_id']
        self.fake=FakeHTTPDocker()
        self.attachments=[]

    def factory(self, cwd):
        return HTTPDockerBroker(cwd,executor=self.fake,attachment_cls=FakeAttachment)

    def run_http(self, checks=None, **kwargs):
        return http_probe_snapshot(self.store,self.sid,'main.py',checks or ['/health=200','/absent=404'],
                                   execute=True,broker_factory=self.factory,**kwargs)

    def test_true_independent_observation_produces_no_security_verdict(self):
        r=self.run_http()
        self.assertEqual(r['status'],'HTTP_CHECKS_PASSED',r)
        self.assertEqual(r['security_verdict'],'NOT_EVALUATED')
        self.assertIsNone(r['finding_status'])
        self.assertEqual(r['cleanup'],'PASS')
        self.assertEqual(len(r['observations']),2)
        self.assertEqual(len(list((self.root/'state'/'http_probes').glob('*/docker_receipt.json'))),1)
        self.assertTrue(all(x['passed'] for x in r['observations']))
        self.assertIn('start',sum((args for args,_ in self.fake.calls),[]))
        # Source passed via stdin to Docker, never as Docker env or host Python.
        self.assertEqual(len(FakeAttachment.inputs[-1][1]) > 0,True)
        self.assertFalse(any('SL_HTTP_CONTRACT' in str(args) and 'task.py' in str(args) for args,_ in self.fake.calls))
    def test_expected_failure_is_not_fixed(self):
        self.fake.status_override=401
        r=self.run_http()
        self.assertEqual(r['status'],'HTTP_CHECKS_FAILED',r)
        self.assertEqual(r['security_verdict'],'NOT_EVALUATED')
        self.assertIsNone(r['finding_status'])
    def test_tampered_verifier_binding_blocked(self):
        self.fake.verifier_problem='bad-nonce'
        r=self.run_http()
        self.assertEqual(r['status'],'BLOCKED')
        self.assertIn('binding',r['error'])
    def test_verifier_self_contradiction_blocked(self):
        self.fake.verifier_problem='self-contradiction'
        r=self.run_http()
        self.assertEqual(r['status'],'BLOCKED')
    def test_verifier_timeout_unreachable_and_fake_pass_string_blocked(self):
        for failure in ('timeout','garbage','unreachable'):
            with self.subTest(failure=failure):
                self.fake=FakeHTTPDocker();self.fake.verifier_problem=failure
                self.assertEqual(self.run_http()['status'],'BLOCKED')
    def test_unsafe_network_and_container_blocked(self):
        for fault in ('unsafe_network','unsafe_container'):
            with self.subTest(fault=fault):
                self.fake=FakeHTTPDocker()
                setattr(self.fake,fault,True)
                r=self.run_http()
                self.assertEqual(r['status'],'BLOCKED')
                self.assertEqual(r['security_verdict'],'NOT_EVALUATED')
    def test_cleanup_failure_overrides_pass(self):
        self.fake.cleanup_failure=True
        self.assertEqual(self.run_http()['status'],'BLOCKED')
    def test_snapshot_modified_rejected_before_docker(self):
        (Path(self.snapshot['workspace'])/'main.py').write_text('print("attacker")\n',encoding='utf-8')
        with self.assertRaises(PolicyError):
            self.run_http()
        self.assertEqual(self.fake.calls,[])
    def test_opt_in_or_check_missing_never_contacts_docker(self):
        with self.assertRaisesRegex(PolicyError,'explicit --execute'):
            http_probe_snapshot(self.store,self.sid,'main.py',['/health=200'],broker_factory=self.factory)
        with self.assertRaises(PolicyError):
            self.run_http(['//invalid=200'])
        self.assertEqual(self.fake.calls,[])
    def test_cli_requires_opt_in_and_scan_stays_blocked(self):
        out=io.StringIO();err=io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            ret=main(['--state',str(self.store.root),'repo','http-probe',self.sid,
                      '--entry','main.py','--expect','/health=200'])
        self.assertEqual(ret,2)
        self.assertIn('explicit --execute',err.getvalue())
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            ret=main(['--state',str(self.store.root),'scan',str(self.project)])
        self.assertEqual(ret,2)
    def test_code_is_never_executed_on_host(self):
        marker=self.root/'host_marker'
        (self.project/'main.py').write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("HI")\n',encoding='utf-8')
        sid=create_snapshot(self.store,add_project(self.store,self.project,'another')['id'])['snapshot_id']
        self.sid=sid
        self.run_http()
        self.assertFalse(marker.exists())

if __name__=='__main__':
    unittest.main()
