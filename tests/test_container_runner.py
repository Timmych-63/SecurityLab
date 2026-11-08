import json
from pathlib import Path
import sys
import tempfile
import unittest
from securitylab.container_runner import DockerBroker, create_args
from securitylab.job_contract import job_bytes, parse_job, MAX_PAYLOAD
from securitylab.policy import Limits, PolicyError
from securitylab.process import Result, execute

IMAGE = 'sha256:' + 'a'*64

def response(stdout='', code=0, **kw):
    values = dict(command=[], returncode=code, stdout=stdout, stderr='', timed_out=False,
                  cancelled=False, truncated=False, duration=0.01)
    values.update(kw)
    return Result(**values)

class FakeDocker:
    """Contract tests only. This is never reported as a live Docker integration."""
    def __init__(self):
        self.calls=[]; self.endpoint='npipe:////./pipe/dockerDesktopLinuxEngine'
        self.start=response('hello\n');self.exitcode=0;self.remaining='';self.volumes=None
        self.unsafe_mount=False;self.raise_start=False;self.oom=False;self.before_create=None
    def __call__(self, argv, cwd, limits, **kwargs):
        self.calls.append((argv,kwargs))
        args = argv[3:] if argv[1:2] == ['--host'] else argv[1:]
        if args[:2] == ['context','inspect']: return response(self.endpoint)
        if args[:2] == ['image','inspect']:
            return response(json.dumps([{'Id':IMAGE,'Config':{'Volumes':self.volumes}}]))
        if args[0]=='create':
            if self.before_create: self.before_create()
            return response('b'*64)
        if args[0]=='inspect' and '--format' not in args:
            mounts=[{'Type':'bind'}] if self.unsafe_mount else []
            return response(json.dumps([{'Config':{'Image':IMAGE,'User':'10001:10001'},
                'HostConfig':{'Privileged':False,'NetworkMode':'none','ReadonlyRootfs':True,
                              'Binds':None,'PidMode':'','IpcMode':'private','CapDrop':['ALL'],
                              'SecurityOpt':['no-new-privileges:true'],'Memory':536870912,
                              'MemorySwap':536870912,'NanoCpus':1000000000,'PidsLimit':64,
                              'Tmpfs':{'/tmp':'opts','/work':'opts'}}, 'Mounts':mounts}]))
        if args[0]=='start':
            if self.raise_start: raise OSError('transport broke')
            return self.start
        if args[0]=='inspect':
            return response(json.dumps({'Running':False,'ExitCode':self.exitcode,'OOMKilled':self.oom,'Error':''}))
        if args[0]=='rm':return response('removed')
        if args[0]=='ps':return response(self.remaining)
        raise AssertionError(argv)

class ContractTests(unittest.TestCase):
    def test_unicode_roundtrip(self):
        files={'task.py':'print("Привет 😀")'}
        self.assertEqual(parse_job(job_bytes(files))['files'], files)
    def test_shell_mount_and_image_fields_rejected(self):
        for field in ('command','shell','mounts','image','timeout'):
            with self.assertRaises(PolicyError):
                parse_job(json.dumps({'schema_version':1,'files':{'task.py':''},field:'bad'}).encode())
    def test_path_and_case_collisions(self):
        for name in ('../evil.py','/etc/test.py','a/b.py','x\\y.py','.git/config','bad name.py','TASK.py'):
            with self.subTest(name=name), self.assertRaises(PolicyError):
                job_bytes({'task.py':'',name:''})
    def test_missing_entry_wrong_type_and_version(self):
        for body in ({'schema_version':True,'files':{'task.py':''}},
                     {'schema_version':2,'files':{'task.py':''}},
                     {'schema_version':1,'files':{'foo.py':''}},
                     {'schema_version':1,'files':{'task.py':42}}):
            with self.assertRaises(PolicyError):parse_job(json.dumps(body).encode())
    def test_duplicate_json_keys(self):
        with self.assertRaises(PolicyError):
            parse_job(b'{"schema_version":1,"files":{"task.py":"x","task.py":"y"}}')
    def test_payload_bound(self):
        with self.assertRaises(PolicyError):parse_job(b' '* (MAX_PAYLOAD+1))
    def test_no_control_of_docker_args(self):
        args=create_args(IMAGE,'securitylab-job-'+'a'*32)
        for flag in ('--interactive','--init','--read-only','--cap-drop','--memory','--pids-limit'):
            self.assertIn(flag,args)
        for flag in ('--privileged','--volume','--mount','--publish','--volumes-from'):
            self.assertNotIn(flag,args)
        self.assertEqual(args[args.index('--network')+1],'none')
        self.assertEqual(args[args.index('--log-driver')+1],'none')
    def test_bad_image_or_name_rejected(self):
        for image,name in (('python:latest','securitylab-job-'+'a'*32),(IMAGE,'--privileged')):
            with self.assertRaises(PolicyError):create_args(image,name)

class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.fake=FakeDocker()
    def tearDown(self):self.tmp.cleanup()
    def run_job(self):
        broker=DockerBroker(self.root,self.fake)
        result=broker.run(job_bytes({'task.py':'print("hello")'}),self.root/'results')
        self.assertTrue((self.root/'results'/(result['id']+'.json')).is_file())
        self.assertIn('UNTRUSTED',result['output_trust'])
        return result
    def test_intent_saved_before_create(self):
        def assert_intent():
            records=list((self.root/'results').glob('*.json'))
            self.assertEqual(len(records),1)
            self.assertEqual(json.loads(records[0].read_text(encoding='utf-8'))['cleanup'],'NOT_TESTED')
        self.fake.before_create=assert_intent
        self.run_job()
    def test_image_lookup_does_not_require_existing_containers(self):
        broker=DockerBroker(self.root,self.fake)
        self.assertEqual(broker.image_id,IMAGE)
        self.assertTrue(any(argv[-3:]==['image','inspect','securitylab-demo:local'] for argv,_ in self.fake.calls))
        self.assertFalse(any('compose' in argv for argv,_ in self.fake.calls))
    def test_completed_job_is_not_fixed(self):
        r=self.run_job();self.assertEqual(r['status'],'COMPLETED');self.assertEqual(r['cleanup'],'PASS')
        self.assertNotIn('FIXED',json.dumps(r))
        start=next(c for c in self.fake.calls if 'start' in c[0])
        self.assertIn('task.py',start[1]['input_data'].decode())
    def test_exit_code_from_daemon(self):
        self.fake.exitcode=7;self.fake.start=response(code=7)
        self.assertEqual(self.run_job()['status'],'NONZERO_EXIT')
    def test_transport_mismatch(self):
        self.fake.exitcode=7
        self.assertEqual(self.run_job()['status'],'TRANSPORT_ERROR')
    def test_timeout_cleanup(self):
        self.fake.start=response(code=-9,timed_out=True)
        r=self.run_job();self.assertEqual(r['status'],'TIMEOUT');self.assertEqual(r['cleanup'],'PASS')
    def test_output_limit_cleanup(self):
        self.fake.start=response(truncated=True)
        self.assertEqual(self.run_job()['status'],'OUTPUT_LIMIT')
    def test_cleanup_failure_overrides_success(self):
        self.fake.remaining='b'*64
        self.assertEqual(self.run_job()['status'],'CLEANUP_FAILED')
    def test_exception_still_cleans(self):
        self.fake.raise_start=True
        r=self.run_job();self.assertEqual(r['status'],'BLOCKED');self.assertEqual(r['cleanup'],'PASS')
    def test_unsafe_mount_prevents_start(self):
        self.fake.unsafe_mount=True
        self.assertEqual(self.run_job()['status'],'BLOCKED')
        self.assertFalse(any('start' in argv for argv,_ in self.fake.calls))
    def test_remote_endpoint_rejected(self):
        self.fake.endpoint='tcp://other-host:2375'
        with self.assertRaises(PolicyError):DockerBroker(self.root,self.fake)
    def test_implicit_volumes_rejected(self):
        self.fake.volumes={'/data':{}}
        with self.assertRaises(PolicyError):DockerBroker(self.root,self.fake)
    def test_oom_reported(self):
        self.fake.oom=True
        self.assertEqual(self.run_job()['status'],'RESOURCE_LIMIT')
    def test_invalid_job_does_not_create_container(self):
        broker=DockerBroker(self.root,self.fake)
        with self.assertRaises(PolicyError):broker.run(b'{}',self.root/'results')
        self.assertFalse(any('create' in argv for argv,_ in self.fake.calls))

class StdinTransportTests(unittest.TestCase):
    def test_utf8_payload_and_eof(self):
        with tempfile.TemporaryDirectory() as td:
            raw='Привет 😀'.encode()
            r=execute([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],
                      Path(td),Limits(),input_data=raw)
            self.assertTrue(r.passed);self.assertEqual(r.stdout,raw.decode())
    def test_blocked_stdin_is_timed_out(self):
        with tempfile.TemporaryDirectory() as td:
            r=execute([sys.executable,'-c','import time;time.sleep(30)'],Path(td),Limits(timeout=1),input_data=b'x'*262144)
            self.assertTrue(r.timed_out)
    def test_oversize_input_rejected_before_process(self):
        with self.assertRaises(ValueError):execute(['does-not-exist'],Path('.'),Limits(),input_data=b'x'*1048577)
