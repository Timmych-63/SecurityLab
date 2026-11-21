import copy
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from securitylab.cli import main
from securitylab.fixture import FIXED, VULNERABLE, digest, SUITE
from securitylab.gitops import DemoGit
from securitylab.orchestrator import Orchestrator
from securitylab.policy import PolicyError, Limits, safe_path, permit
from securitylab.process import execute
from securitylab.report import report
from securitylab.runner import FixtureRunner
from securitylab.storage import Store, worker_lock
from securitylab.validator import validate, confirmed

class TempTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'state')
        self.engine = Orchestrator(self.store)
    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()
    def complete(self):
        rid = self.store.create()
        result = self.engine.run(rid)
        self.assertEqual(result['stage'], 'DONE', result)
        return rid

class WorkflowTests(TempTest):
    def test_complete_proven_fix_and_main_untouched(self):
        rid = self.complete()
        self.assertEqual(self.store.finding(rid)['status'], 'FIXED')
        git = DemoGit(self.engine.repo(rid))
        self.assertEqual(git.call('show', 'main:service.py') + '\n', VULNERABLE)
        self.assertEqual(git.call('branch', '--show-current'), 'securitylab/' + rid[:12])
        e = self.store.evidence(rid)
        self.assertEqual(e['baseline']['result']['returncode'], 1)
        self.assertEqual(e['baseline']['test_hash'], e['recheck']['test_hash'])
        self.assertNotEqual(e['baseline']['revision'], e['recheck']['revision'])
        self.assertEqual(e['verdict']['status'], 'FIXED')
        self.assertEqual(len(self.store.history(rid)), 7)
        self.assertTrue(git.clean())

    def test_reopen_database_and_idempotent_done(self):
        rid = self.complete()
        self.store.close()
        self.store = Store(self.root / 'state')
        before = self.store.history(rid)
        Orchestrator(self.store).run(rid)
        self.assertEqual(before, self.store.history(rid))

    def test_resume_after_each_stage(self):
        class Crash(BaseException): pass
        for stage in ('DISCOVERED', 'CONFIRMED', 'PATCHED', 'VERIFIED'):
            with self.subTest(stage=stage):
                rid = self.store.create()
                def crash(current):
                    if current == stage: raise Crash()
                with self.assertRaises(Crash):
                    self.engine.run(rid, after_stage=crash)
                self.assertEqual(self.store.get(rid)['stage'], stage)
                self.engine.run(rid)
                self.assertEqual(self.store.finding(rid)['status'], 'FIXED')
                self.assertEqual(self.store.get(rid)['attempts'], 2)

    def test_recover_partial_git_patch_before_state_commit(self):
        class Crash(BaseException): pass
        rid = self.store.create()
        def crash(stage):
            if stage == 'CONFIRMED': raise Crash()
        with self.assertRaises(Crash): self.engine.run(rid, after_stage=crash)
        self.engine.patch(self.engine.repo(rid), rid)
        commit = DemoGit(self.engine.repo(rid)).head()
        self.engine.run(rid)
        self.assertEqual(DemoGit(self.engine.repo(rid)).head(), commit)
        self.assertEqual(self.store.finding(rid)['status'], 'FIXED')

    def test_stop_and_retry(self):
        rid = self.store.create()
        self.store.stop(rid)
        self.engine.run(rid)
        self.assertEqual(self.store.get(rid)['status'], 'STOPPED')
        self.assertFalse(self.engine.repo(rid).exists())
        self.store.retry(rid, 3)
        self.engine.run(rid)
        self.assertEqual(self.store.get(rid)['status'], 'DONE')

    def test_retry_limit(self):
        rid = self.store.create()
        for i in range(3):
            self.store.stop(rid)
            self.engine.run(rid)
            if i < 2: self.store.retry(rid, 3)
        with self.assertRaises(PolicyError): self.store.retry(rid, 3)

    def test_illegal_transition_rollback(self):
        rid = self.store.create()
        self.store.begin(rid, 3)
        with self.assertRaises(PolicyError): self.store.advance(rid, 'QUEUED', 'DONE')
        self.assertEqual(self.store.get(rid)['stage'], 'QUEUED')
        with self.assertRaises(PolicyError):
            self.store.advance(rid, 'DISCOVERED', 'CONFIRMED', {'bad': {'claim':'fixed'}})
        self.assertEqual(self.store.evidence(rid), {})

    def test_host_modified_code_denied(self):
        rid = self.store.create()
        self.engine.initialise_fixture(self.engine.repo(rid))
        marker = self.root / 'owned'
        (self.engine.repo(rid) / 'service.py').write_text('open(' + repr(str(marker)) + ',"w").write("oops")', encoding='utf-8')
        with self.assertRaises(PolicyError):
            self.engine.runner.suite(self.engine.repo(rid), 'fake', False)
        self.assertFalse(marker.exists())

    def test_worker_lock_excludes_second_process(self):
        script = 'from pathlib import Path; from securitylab.storage import worker_lock; import sys;\nwith worker_lock(Path(sys.argv[1])): pass'
        with worker_lock(self.store.root):
            p = subprocess.run([sys.executable, '-c', script, str(self.store.root)], capture_output=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b'Another worker', p.stderr)
        self.assertIn(str(self.store.root).encode(), p.stderr)
        self.assertIn(b'stop the previous dashboard', p.stderr)
        with worker_lock(self.store.root): pass

    def test_events_export_recreated(self):
        rid = self.complete()
        output = self.root / 'events.jsonl'
        output.write_text('broken', encoding='utf-8')
        self.store.export_events(rid, output)
        self.assertEqual([json.loads(x) for x in output.read_text(encoding='utf-8').splitlines()], self.store.history(rid))

class ValidatorTests(TempTest):
    def setUp(self):
        super().setUp()
        self.rid = self.complete()
        self.e = self.store.evidence(self.rid)
        self.revision = self.e['recheck']['revision']
        self.base = self.e['baseline']['revision']
    def check(self, e):
        return validate(e, self.revision, True, self.base)['status']
    def test_rejects_model_claim_without_evidence(self):
        self.assertEqual(self.check({'status': 'FIXED'}), 'NEEDS_REVIEW')
    def test_every_required_proof_is_required(self):
        for key in ('baseline', 'regression', 'recheck', 'mandatory', 'build'):
            e = copy.deepcopy(self.e); del e[key]
            self.assertEqual(self.check(e), 'NEEDS_REVIEW', key)
    def test_stale_commit_rejected(self):
        e = copy.deepcopy(self.e); e['regression']['revision'] = self.base
        self.assertEqual(self.check(e), 'NEEDS_REVIEW')
    def test_changed_test_rejected(self):
        e = copy.deepcopy(self.e); e['recheck']['test_hash'] = digest('assert True')
        self.assertEqual(self.check(e), 'NEEDS_REVIEW')
    def test_false_success_zero_exit_not_enough(self):
        e = copy.deepcopy(self.e); e['recheck']['checks'] = {}
        self.assertEqual(self.check(e), 'NEEDS_REVIEW')
    def test_timed_out_truncated_cancelled_rejected(self):
        for flag in ('timed_out', 'truncated', 'cancelled'):
            e = copy.deepcopy(self.e); e['mandatory']['result'][flag] = True
            self.assertEqual(self.check(e), 'NEEDS_REVIEW')
    def test_baseline_crash_not_vulnerability(self):
        e = copy.deepcopy(self.e['baseline']); e['checks'] = {}
        self.assertFalse(confirmed(e))
    def test_dirty_worktree_rejected(self):
        self.assertEqual(validate(self.e, self.revision, False, self.base)['status'], 'NEEDS_REVIEW')
    def test_changed_main_rejected(self):
        self.assertEqual(validate(self.e, self.revision, True, self.revision)['status'], 'NEEDS_REVIEW')
    def test_nonboolean_checks_rejected(self):
        e = copy.deepcopy(self.e); e['recheck']['checks']['owner_read'] = 'true'
        self.assertEqual(self.check(e), 'NEEDS_REVIEW')

class PolicyTests(TempTest):
    def test_path_traversal_and_git_paths_denied(self):
        for value in ('../escape', '/tmp/escape', '.git/config', 'x/../../escape', 'C:\\x', 'a\\b'):
            with self.subTest(value=value), self.assertRaises(PolicyError): safe_path(self.root, value)
    @unittest.skipIf(os.name == 'nt', 'Symlink privilege not assumed on Windows')
    def test_symlink_escape_denied(self):
        (self.root / 'link').symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaises(PolicyError): safe_path(self.root, 'link/file')
    def test_roles_cannot_close_execute_or_merge(self):
        for role in ('red', 'blue', 'unknown'):
            for action in ('close', 'execute', 'merge', 'write_evidence'):
                with self.assertRaises(PolicyError): permit(role, action)
        permit('red', 'propose_finding'); permit('blue', 'propose_patch')
    def test_invalid_limits(self):
        for kwargs in ({'timeout':0}, {'max_attempts':999}, {'output_bytes':1}):
            with self.assertRaises(PolicyError): Limits(**kwargs)
    def test_unknown_id_rejected(self):
        with self.assertRaises(PolicyError): self.store.get('../oops')
        with self.assertRaises(PolicyError): self.store.get('a' * 32)

class ProcessTests(TempTest):
    def test_timeout(self):
        result = execute([sys.executable, '-c', 'import time; time.sleep(10)'], self.root, Limits(timeout=1))
        self.assertTrue(result.timed_out)
        self.assertFalse(result.passed)
        self.assertLess(result.duration, 5)
    def test_cancel(self):
        result = execute([sys.executable, '-c', 'import time; time.sleep(10)'], self.root, Limits(), lambda: True)
        self.assertTrue(result.cancelled)
        self.assertFalse(result.passed)
    def test_output_bounded(self):
        result = execute([sys.executable, '-c', 'print("X"*100000)'], self.root, Limits(output_bytes=1024))
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.stdout), 1024)
    def test_stderr_and_nonzero(self):
        result = execute([sys.executable, '-c', 'import sys; print("bad",file=sys.stderr);sys.exit(9)'], self.root, Limits())
        self.assertEqual(result.returncode, 9)
        self.assertIn('bad', result.stderr)

class ReportCliTests(TempTest):
    def test_html_escapes_findings_and_json_has_proofs(self):
        rid = self.complete()
        f = self.store.finding(rid); f['title'] = '<script>alert(1)</script> Кириллица 😀'
        with self.store.db:
            self.store.db.execute('UPDATE findings SET body=? WHERE run_id=?', (json.dumps(f), rid))
        path = report(self.store, rid, self.root / 'report')
        text = path.read_text(encoding='utf-8')
        self.assertNotIn('<script>', text)
        self.assertIn('&lt;script&gt;', text)
        self.assertIn('Content-Security-Policy', text)
        self.assertEqual(json.loads(path.with_suffix('.json').read_text(encoding='utf-8'))['evidence']['verdict']['status'], 'FIXED')
    def test_cli_end_to_end(self):
        args = ['--state', str(self.root / 'cli')]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(args + ['demo', '--enqueue']), 0)
            rid = json.loads(out.getvalue())['id']
        for command in (['worker', '--run', rid], ['status', rid], ['findings', rid], ['history', rid], ['report', rid]):
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(main(args + command), 0)
    def test_scan_fails_closed_without_touching_project(self):
        project = self.root / 'my-project'; project.mkdir()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['scan', str(project)]), 2)
        self.assertEqual(list(project.iterdir()), [])

if __name__ == '__main__': unittest.main()

class ConfigurationTests(TempTest):
    def test_valid_configuration(self):
        from securitylab.config import load_limits
        p = self.root / 'config.toml'; p.write_text('[limits]\ntimeout=5\nmax_attempts=2\n', encoding='utf-8')
        self.assertEqual(load_limits(p).timeout, 5)
    def test_unknown_and_boolean_values_rejected(self):
        from securitylab.config import load_limits
        for text in ('[limits]\ncommand="sh"', '[limits]\ntimeout=true', '[network]\nallow=true'):
            p = self.root / 'config.toml'; p.write_text(text, encoding='utf-8')
            with self.assertRaises(PolicyError): load_limits(p)

class RecoveryRollbackTests(TempTest):
    def test_actual_process_death_releases_lock_and_resumes(self):
        rid = self.store.create()
        code = '''import os, sys
from pathlib import Path
from securitylab.storage import Store
from securitylab.orchestrator import Orchestrator
s=Store(Path(sys.argv[1]))
def crash(stage):
    if stage == 'CONFIRMED': os._exit(77)
Orchestrator(s).run(sys.argv[2], after_stage=crash)
'''
        child = subprocess.run([sys.executable, '-c', code, str(self.store.root), rid], capture_output=True)
        self.assertEqual(child.returncode, 77, child.stderr)
        self.assertEqual(self.store.get(rid)['stage'], 'CONFIRMED')
        self.engine.run(rid)
        self.assertEqual(self.store.finding(rid)['status'], 'FIXED')

    def test_rollback_preserves_main_and_is_idempotent(self):
        rid = self.complete()
        git = DemoGit(self.engine.repo(rid)); main = git.call('rev-parse', 'main')
        result = self.engine.rollback(rid)
        self.assertEqual(result['status'], 'ROLLED_BACK')
        self.assertEqual(self.store.finding(rid)['status'], 'REOPENED_AFTER_ROLLBACK')
        self.assertEqual(git.call('rev-parse', 'main'), main)
        self.assertEqual((self.engine.repo(rid) / 'service.py').read_text(encoding='utf-8'), VULNERABLE)
        self.assertEqual(git.call('diff', 'main', 'HEAD', '--'), '')
        head = git.head(); self.engine.rollback(rid); self.assertEqual(git.head(), head)

    def test_rollback_refuses_unknown_changes(self):
        rid = self.complete()
        (self.engine.repo(rid) / 'user.txt').write_text('preserve me', encoding='utf-8')
        with self.assertRaises(PolicyError): self.engine.rollback(rid)
        self.assertEqual((self.engine.repo(rid) / 'user.txt').read_text(encoding='utf-8'), 'preserve me')


class WindowsEncodingTests(TempTest):
    # Only run the focused inherited HTML scenario under a simulated CP1251 default.
    def test_report_with_cp1251_default(self):
        from unittest.mock import patch
        original = Path.read_text
        def windows_read(path, encoding=None, errors=None):
            return original(path, encoding=encoding or 'cp1251', errors=errors)
        with patch.object(Path, 'read_text', windows_read):
            ReportCliTests.test_html_escapes_findings_and_json_has_proofs(self)
