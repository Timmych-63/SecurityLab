import copy
import errno
import unittest
from securitylab.sandbox_check import evaluate, mount_options

class SandboxChecks(unittest.TestCase):
    def setUp(self):
        self.good = {'uid':10001, 'CapEff':'0000', 'CapPrm':'0000', 'CapBnd':'0000',
                     'NoNewPrivs':'1', 'Seccomp':'2', 'interfaces':['lo'],
                     'network_errno':errno.ENETUNREACH, 'root_options':['ro'],
                     'tmp_options':['rw','noexec','nosuid','nodev'],
                     'data_writable':True, 'tmp_writable':True, 'docker_socket_absent':True,
                     'memory.max':'536870912', 'pids.max':'64', 'cpu.max':'100000 100000'}
    def test_expected_configuration(self):
        self.assertEqual(evaluate(self.good)['status'], 'PASS')
        self.assertEqual(len(evaluate(self.good)['checks']), 16)
    def test_missing_observation_is_blocked(self):
        for key in self.good:
            with self.subTest(key=key):
                s=copy.deepcopy(self.good);del s[key]
                self.assertEqual(evaluate(s)['status'],'BLOCKED')
    def test_unsafe_observations_fail(self):
        bad={'uid':0,'CapEff':'1','CapPrm':'1','CapBnd':'1','NoNewPrivs':'0','Seccomp':'0',
             'interfaces':['lo','eth0'],'network_errno':0,'root_options':['rw'],
             'tmp_options':['rw'],'data_writable':False,'tmp_writable':False,
             'docker_socket_absent':False,'memory.max':'max','pids.max':'max','cpu.max':'max 100000'}
        for key,value in bad.items():
            with self.subTest(key=key):
                s=self.good|{key:value};self.assertEqual(evaluate(s)['status'],'FAIL')
    def test_timeout_not_proof_of_isolation(self):
        self.assertEqual(evaluate(self.good|{'network_errno':errno.ETIMEDOUT})['status'],'FAIL')
    def test_malformed_limits_fail(self):
        for key in ('memory.max','pids.max','cpu.max'):
            for value in ('0','-1','nonsense','100000 0'):
                with self.subTest(key=key,value=value):
                    self.assertEqual(evaluate(self.good|{key:value})['status'],'FAIL')
    def test_larger_limits_fail(self):
        for key,value in (('memory.max','1073741824'),('pids.max','128'),('cpu.max','200000 100000')):
            self.assertEqual(evaluate(self.good|{key:value})['status'],'FAIL')
    def test_mount_parser_matches_exact_mount(self):
        text='overlay / overlay ro,relatime 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n'
        self.assertEqual(mount_options(text,'/'),{'ro','relatime'})
        self.assertIn('noexec',mount_options(text,'/tmp'))
        self.assertEqual(mount_options(text,'/missing'),set())
