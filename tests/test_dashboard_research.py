"""Dashboard research wiring: preparation API, validation, grant, launch."""
import contextlib
import json
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest

from securitylab.dashboard import Dashboard
from securitylab.policy import PolicyError
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot
from securitylab.storage import Store

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ('# Тестовое приложение\n\nНазначение: чтение записей.\n\n'
             '## Права\nalice и bob читают только свои записи; чужие — отказ 403.\n')


class DashboardResearchTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.profiles = self.tmp / 'profiles'
        self.profiles.mkdir()
        self.policies = ROOT / 'examples' / 'security_policies'
        self.app = Dashboard(self.tmp / 'state', self.profiles, self.policies)
        self.src = self.tmp / 'project'
        shutil.copytree(ROOT / 'examples/s7_repos/authz_vulnerable', self.src)
        with contextlib.closing(Store(self.app.root)) as s:
            pid = add_project(s, self.src)['id']
            self.sid = create_snapshot(s, pid)['snapshot_id']
            self.pid = pid
        self.knowledge = KNOWLEDGE
        self.data = {'snapshotId': self.sid, 'service': '.', 'entryModule': 'app/main.py',
                     'knowledgeText': self.knowledge,
                     'actors': {'alice': 'user', 'bob': 'user'},
                     'budget': {'seconds': 600, 'decisions': 6, 'requests': 10}}

    def test_prepare_creates_preparation_and_supersedes_previous(self):
        first = self.app.dispatch('POST', '/api/research/prepare', dict(self.data))
        self.assertEqual(first['status'], 'PREPARED')
        second = self.app.dispatch('POST', '/api/research/prepare', dict(self.data))
        rows = self.app.dispatch('GET', '/api/research')
        by_id = {r['id']: r for r in rows}
        self.assertEqual(by_id[first['preparationId']]['status'], 'SUPERSEDED')
        self.assertEqual(by_id[first['preparationId']]['supersededBy'], second['preparationId'])
        self.assertEqual(by_id[second['preparationId']]['status'], 'PREPARED')
        with self.assertRaises(PolicyError):
            self.app.dispatch('POST', '/api/research/prepare',
                              dict(self.data, actors={'bad name': 'user'}))
        with self.assertRaises(PolicyError):
            self.app.dispatch('POST', '/api/research/prepare',
                              dict(self.data, budget={'seconds': 5, 'decisions': 1, 'requests': 1}))

    def test_research_input_validation_and_launch(self):
        prep = self.app.dispatch('POST', '/api/research/prepare', dict(self.data))
        inp = {'projectId': self.pid, 'snapshotId': self.sid, 'service': '.',
               'entryModule': 'app/main.py', 'profileId': 'research-v1',
               'preparationId': prep['preparationId'], 'aiConfigId': 'default',
               'stateDir': str(self.app.root)}
        cfg, summary, mapping = self.app.validate_input(inp)
        self.assertEqual(summary['status'], 'PREPARED')
        self.assertTrue(any(r['path'] == '/records/{record_id}' for r in mapping['routes']))
        # Entry mismatch is rejected before any model call.
        with self.assertRaises(PolicyError):
            self.app.validate_input(dict(inp, entryModule='app/other.py'))
        with self.assertRaises(PolicyError):
            self.app.validate_input(dict(inp, preparationId='0' * 32))
        # Superseded preparation cannot be launched.
        self.app.dispatch('POST', '/api/research/prepare', dict(self.data))
        with self.assertRaises(PolicyError):
            self.app.validate_input(inp)
        fresh = self.app.dispatch('POST', '/api/research/prepare', dict(self.data))
        inp2 = dict(inp, preparationId=fresh['preparationId'])
        entered = threading.Event()
        release = threading.Event()
        self.addCleanup(release.set)
        received = {}

        def runner(store, preparation_id, **kw):
            received['prep'] = preparation_id
            received['stop'] = kw.get('stop')
            received['progress'] = kw.get('progress')
            received['execute'] = kw.get('execute')
            entered.set()
            release.wait(3)
            return {'status': 'DONE', 'hypotheses': [], 'coverage': {'decisions_used': 0}}

        self.app.research_runner = runner
        self.app.grants[json.dumps(inp2, sort_keys=True)] = (time.monotonic(), cfg.sha256)
        result = self.app.launch(inp2)
        self.assertTrue(entered.wait(3))
        self.assertEqual(received['prep'], fresh['preparationId'])
        self.assertTrue(received['execute'])
        saved = json.loads((self.app.jobs / (result['runId'] + '.json')).read_text())
        self.assertEqual(saved['preparation']['id'], fresh['preparationId'])
        self.assertIn('budget', saved['preparation'])
        release.set()
        for _ in range(200):
            if self.app.active is None:
                break
            time.sleep(0.01)
        view = self.app.run(result['runId'])
        self.assertEqual(view['profileId'], 'research-v1')
        self.assertEqual(view['mode'], 'S7_2_ACCESS_AI_SINGLE_MODULE')  # summary is runner's minimal dict
        self.assertEqual(view['exec'], 'completed')

    def test_launch_requires_fresh_grant(self):
        prep = self.app.dispatch('POST', '/api/research/prepare', dict(self.data))
        inp = {'projectId': self.pid, 'snapshotId': self.sid, 'service': '.',
               'entryModule': 'app/main.py', 'profileId': 'research-v1',
               'preparationId': prep['preparationId'], 'aiConfigId': 'default',
               'stateDir': str(self.app.root)}
        with self.assertRaises(PolicyError):
            self.app.launch(inp)


if __name__ == '__main__':
    unittest.main()
