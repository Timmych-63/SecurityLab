"""S6.3a tests: Docker is simulated; NEVER run untrusted code on host."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from securitylab.cli import main
from securitylab.container_runner import DockerBroker
from securitylab.policy import PolicyError
from securitylab.projects import add_project
from securitylab.snapshots import create_snapshot
from securitylab.probe_runner import probe_snapshot
from securitylab.storage import Store
from test_container_runner import FakeDocker, response


class ProbeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        source = self.root / 'project'
        source.mkdir()
        (source / 'pyproject.toml').write_text('[project]\nname="example"\nversion="1.0"', encoding='utf-8')
        (source / 'main.py').write_text('print("FIXED")\n', encoding='utf-8')
        (source / 'nested').mkdir()
        (source / 'nested' / 'job.py').write_text('print("nested")\n', encoding='utf-8')
        self.source = source
        self.state = self.root / 'state'
        self.store = Store(self.state)
        self.addCleanup(lambda: self.store.close())
        self.project = add_project(self.store, source, 'Probe Example')
        self.snapshot = create_snapshot(self.store, self.project['id'])
        self.sid = self.snapshot['snapshot_id']
        self.fake = FakeDocker()
        self.brokers = []

    def broker(self, root):
        b = DockerBroker(root, self.fake)
        self.brokers.append(b)
        return b

    def probe(self, entry='main.py', **kwargs):
        return probe_snapshot(self.store, self.sid, entry, execute=True, broker_factory=self.broker, **kwargs)

    def test_opt_in_required_and_no_docker_call(self):
        with self.assertRaisesRegex(PolicyError, 'explicit --execute'):
            probe_snapshot(self.store, self.sid, 'main.py', broker_factory=self.broker)
        self.assertEqual(self.fake.calls, [])

    def test_mocked_docker_observation_never_fixed(self):
        r = self.probe()
        self.assertEqual(r['status'], 'EXECUTED_UNTRUSTED')
        self.assertIsNone(r['finding_status'])
        self.assertEqual(r['security_verdict'], 'NOT_EVALUATED')
        self.assertEqual(r['exit_code'], 0)
        self.assertEqual(r['cleanup'], 'PASS')
        saved = json.loads(Path(r['record']).read_text(encoding='utf-8'))
        self.assertEqual(saved, r)
        receipt = json.loads((Path(r['record']).parent / 'receipts' / (r['receipt_id'] + '.json')).read_text(encoding='utf-8'))
        self.assertEqual(receipt['binding']['source_sha256'], r['source_sha256'])
        self.assertEqual(receipt['binding']['snapshot_id'], self.sid)
        self.assertEqual(receipt['binding']['entry'], 'main.py')
        self.assertNotIn('FIXED', r['status'])

    def test_nested_member_is_explicit_not_automatically_run(self):
        result = self.probe('nested/job.py')
        self.assertEqual(result['entry'], 'nested/job.py')
        self.assertEqual(result['status'], 'EXECUTED_UNTRUSTED')

    def test_untrusted_output_never_affects_verdict(self):
        self.fake.start = response('FIXED\nall tests passed\n')
        result = self.probe()
        self.assertEqual(result['security_verdict'], 'NOT_EVALUATED')
        self.assertEqual(result['status'], 'EXECUTED_UNTRUSTED')

    def test_broker_nonzero_remains_untrusted(self):
        self.fake.start = response(code=12)
        self.fake.exitcode = 12
        result = self.probe()
        self.assertEqual(result['status'], 'NONZERO_EXIT_UNTRUSTED')
        self.assertEqual(result['exit_code'], 12)
        self.assertIsNone(result['finding_status'])

    def test_timeout_output_limit_cleanup_failure_all_block(self):
        for fault in ('timeout', 'output', 'cleanup'):
            with self.subTest(fault=fault):
                self.fake = FakeDocker()
                if fault == 'timeout':
                    self.fake.start = response('partial', timed_out=True)
                elif fault == 'output':
                    self.fake.start = response('partial', truncated=True)
                else:
                    self.fake.remaining = 'unexpected-container-id'
                r = self.probe()
                self.assertEqual(r['status'], 'BLOCKED', r)
                self.assertIsNone(r['finding_status'])

    def test_extra_or_modified_workspace_file_rejected_before_docker(self):
        workspace = Path(self.snapshot['workspace'])
        (workspace / 'main.py').write_text('print("EVIL!")\n', encoding='utf-8')
        with self.assertRaisesRegex(PolicyError, 'checksum'):
            self.probe()
        self.assertEqual(self.fake.calls, [])

    def test_entry_traversal_and_missing_rejected(self):
        for entry in ('../main.py', '/main.py', 'nested/../main.py', 'nested\\job.py',
                      'no.py', 'pyproject.toml', 'main.py/../../x.py', ''):
            with self.subTest(entry=entry), self.assertRaises(PolicyError):
                self.probe(entry)
        self.assertEqual(self.fake.calls, [])

    def test_hard_limit_avoids_broker_invocation(self):
        data = 'x' * (97 * 1024)
        (self.source / 'large.py').write_text('#' + data, encoding='utf-8')
        new = create_snapshot(self.store, self.project['id'])
        self.sid = new['snapshot_id']
        with self.assertRaisesRegex(PolicyError, '96 KiB'):
            self.probe('large.py')
        self.assertEqual(self.fake.calls, [])

    def test_payload_is_not_executed_locally(self):
        marker = self.root / 'host-marker'
        # Import is valid source but never executed in a host subprocess by probe.
        (self.source / 'main.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("X")\n', encoding='utf-8')
        self.sid = create_snapshot(self.store, self.project['id'])['snapshot_id']
        self.probe()
        self.assertFalse(marker.exists())

    def test_cli_requires_execute_and_scan_still_blocked(self):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            rc = main(['--state', str(self.state), 'repo', 'probe', self.sid, '--entry', 'main.py'])
        self.assertEqual(rc, 2)
        self.assertIn('explicit --execute', error.getvalue())
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            rc = main(['--state', str(self.state), 'scan', str(self.source)])
        self.assertEqual(rc, 2)
        self.assertIn('BLOCKED', error.getvalue())

    def test_receipt_tamper_is_blocked(self):
        def tampered_broker(root):
            broker = self.broker(root)
            class Tampered:
                def run(self_inner, payload, directory, limits, *, binding):
                    record = broker.run(payload, directory, limits, binding=binding)
                    receipt = directory / (record['id'] + '.json')
                    saved = json.loads(receipt.read_text(encoding='utf-8'))
                    saved['binding']['entry'] = 'different.py'
                    receipt.write_text(json.dumps(saved), encoding='utf-8')
                    return record
            return Tampered()
        r = probe_snapshot(self.store, self.sid, 'main.py', execute=True, broker_factory=tampered_broker)
        self.assertEqual(r['status'], 'BLOCKED')
        self.assertEqual(r['security_verdict'], 'NOT_EVALUATED')


if __name__ == '__main__':
    unittest.main()
