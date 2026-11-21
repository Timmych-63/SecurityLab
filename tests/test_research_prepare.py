import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from securitylab.research_prepare import prepare_research, read_document, validate_setup
from securitylab.policy import PolicyError
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot
from securitylab.storage import Store

HERE = Path(__file__).resolve().parents[1]

class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = json.loads((HERE/'examples/research/ticketdesk.setup.json').read_text())

    def test_limits_and_unknown_fields(self):
        for config in [dict(self.config, command='anything'),
                       dict(self.config, budget=dict(self.config['budget'], seconds=True)),
                       dict(self.config, budget=dict(self.config['budget'], requests=101)),
                       dict(self.config, actors={'alice': ['user']}),
                       dict(self.config, runtime='external-url')]:
            with self.subTest(config=config), self.assertRaises(PolicyError):
                validate_setup(config)

    def test_document_rejects_empty_large_invalid_and_link(self):
        doc = self.root/'knowledge.md'
        for raw in [b'', b'x'*12289, b'\xff']:
            doc.write_bytes(raw)
            with self.assertRaises(PolicyError): read_document(doc)
        doc.write_text('hello')
        link = self.root/'link.md'
        try: link.symlink_to(doc)
        except OSError: return
        with self.assertRaises(PolicyError): read_document(link)

    def test_real_snapshot_prepare_no_execution_and_input_copies(self):
        src = self.root/'project'
        shutil.copytree(HERE/'examples/s7_repos/authz_vulnerable', src)
        # This statement is parsed only; executing target code would fail the test.
        main = src/'app/main.py'
        main.write_text('raise RuntimeError("DO NOT EXECUTE")\n'+main.read_text())
        store = Store(self.root/'state')
        self.addCleanup(store.db.close)
        sid = create_snapshot(store, add_project(store, src)['id'])['snapshot_id']
        with patch('subprocess.Popen', side_effect=AssertionError('No subprocess during preparation')):
            result = prepare_research(store, sid, 'app/main.py',
                HERE/'examples/research/ticketdesk.md', HERE/'examples/research/ticketdesk.setup.json')
        self.assertEqual(result['status'], 'PREPARED')
        self.assertFalse(result['execution_ready'])
        folder = Path(result['record']).parent
        self.assertEqual((folder/'knowledge.md').read_bytes(), (HERE/'examples/research/ticketdesk.md').read_bytes())
        self.assertTrue(json.loads((folder/'application_map.json').read_text())['routes'])
        self.assertNotIn('checks', result)
        main_snapshot = store.root/'snapshots'/sid/'workspace/app/main.py'
        main_snapshot.write_text('changed')
        with self.assertRaises(PolicyError):
            prepare_research(store, sid, 'app/main.py', HERE/'examples/research/ticketdesk.md', HERE/'examples/research/ticketdesk.setup.json')

    def test_duplicate_setup_key(self):
        path=self.root/'setup.json'
        path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaises(PolicyError):
            prepare_research(None,'unused','app/main.py',HERE/'examples/research/ticketdesk.md',path)
