"""S11.1 acceptance: non-executing intake, binding and truthful Docker readiness."""
import contextlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from securitylab.ai_config import AIConfig
from securitylab.policy import PolicyError
from securitylab.projects import add_project
from securitylab.research_entry import (
    create_research_preparation, load_research_preparation,
    list_research_preparations, research_preflight,
)
from securitylab.snapshots import create_snapshot
from securitylab.storage import Store

ROOT = Path(__file__).resolve().parents[1]


class Profiles:
    def __init__(self): self.config = AIConfig()
    def get(self, name):
        if name != 'default': raise PolicyError('Unknown profile')
        return self.config


class ResearchEntryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'state')
        self.addCleanup(self.store.close)
        self.profiles = Profiles()
        self.project = add_project(self.store, ROOT / 'examples/s7_repos/authz_vulnerable')
        self.snapshot = create_snapshot(self.store, self.project['id'])
        self.payload = {
            'projectId': self.project['id'], 'snapshotId': self.snapshot['snapshot_id'],
            'service': '.', 'entry': 'app/main.py',
            'knowledge': '# TestDesk\nПользователь видит только свои заявки.\n',
            'setupText': (ROOT / 'examples/research/ticketdesk.setup.json').read_text(encoding='utf-8'),
            'aiConfigId': 'default',
        }

    def prepare(self):
        return create_research_preparation(self.store, self.payload, self.profiles)

    def test_intake_pins_inputs_and_never_starts_target(self):
        with patch('subprocess.Popen', side_effect=AssertionError('target executed on host')):
            result = self.prepare()
        self.assertFalse(result['execution_ready'])
        self.assertEqual(result['security_verdict'], 'NOT_EVALUATED')
        self.assertEqual(result['project_id'], self.project['id'])
        self.assertEqual(load_research_preparation(self.store, result['id'])['ai_config_sha256'], self.profiles.config.sha256)
        self.assertEqual(len(list_research_preparations(self.store)), 1)
        self.assertEqual((self.store.root / 'research_preparations' / result['id'] / 'knowledge.md').read_text(), self.payload['knowledge'])

    def test_duplicate_setup_crossproject_and_untrusted_paths_blocked(self):
        payload = dict(self.payload, setupText='{"schema_version":1,"schema_version":1}')
        with self.assertRaises(PolicyError): create_research_preparation(self.store, payload, self.profiles)
        payload = dict(self.payload, projectId='0'*32)
        with self.assertRaises(PolicyError): create_research_preparation(self.store, payload, self.profiles)
        payload = dict(self.payload, entry='../private.py')
        with self.assertRaises(PolicyError): create_research_preparation(self.store, payload, self.profiles)
        with self.assertRaises(PolicyError): load_research_preparation(self.store, '../../private')
        self.assertEqual(list((self.store.root/'research_preparations').glob('*/summary.json')), [])

    def test_real_preflight_success_still_does_not_claim_autonomous_run(self):
        p = self.prepare()
        calls = []
        def docker(): calls.append('docker')
        def model(cfg): calls.append('model'); self.assertIsInstance(cfg, AIConfig)
        def startup(*args, **kwargs):
            calls.append('startup')
            self.assertTrue(kwargs['execute'])
            self.assertEqual(args[3], ['/openapi.json=200'])
            return {'status':'HTTP_CHECKS_PASSED', 'cleanup':'PASS', 'record':'isolated.json'}
        report=research_preflight(self.store,p['id'],self.profiles,docker,model,startup_probe=startup)
        self.assertEqual(calls, ['docker','model','startup'])
        self.assertEqual(report['status'],'STAND_READY')
        self.assertTrue(report['environment_ready'])
        self.assertFalse(report['execution_ready'])
        self.assertEqual(report['security_verdict'],'NOT_EVALUATED')
        self.assertFalse(report['limits_enforced'])

    def test_stale_markdown_or_ai_config_blocks_before_docker(self):
        p = self.prepare()
        folder=self.store.root/'research_preparations'/p['id']
        (folder/'knowledge.md').write_text('changed')
        docker=lambda: self.fail('Docker should not be used')
        report=research_preflight(self.store,p['id'],self.profiles,docker,docker)
        self.assertEqual(report['status'],'BLOCKED')
        self.assertIn('изменены', report['reason'])
        (folder/'knowledge.md').write_text(self.payload['knowledge'])
        self.profiles.config=AIConfig(max_output_tokens=1024)
        report=research_preflight(self.store,p['id'],self.profiles,docker,docker)
        self.assertEqual(report['status'],'BLOCKED')
        self.assertIn('AI-модели', report['reason'])

    def test_snapshot_corruption_is_blocking(self):
        p=self.prepare()
        path=self.store.root/'snapshots'/p['snapshot_id']/'workspace/app/main.py'
        path.write_text('corrupt')
        report=research_preflight(self.store,p['id'],self.profiles,
                                  lambda: self.fail('must stop before Docker'),
                                  lambda _: self.fail('must stop before model'))
        self.assertFalse(report['environment_ready'])
        self.assertIn(report['status'],('BLOCKED',))

    def test_no_fake_startup_on_probe_failure(self):
        p=self.prepare()
        report=research_preflight(self.store,p['id'],self.profiles,
                                  lambda: None, lambda _: None,
                                  startup_probe=lambda *a,**k: {'status':'HTTP_CHECKS_FAILED','cleanup':'PASS'})
        self.assertEqual(report['status'],'BLOCKED')
        self.assertFalse(report['execution_ready'])
        self.assertIn('/openapi.json',report['reason'])

if __name__=='__main__': unittest.main()
