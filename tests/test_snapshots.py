"""S6.2 positive/negative coverage. Uses synthetic repositories only."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from securitylab.cli import main
from securitylab.policy import PolicyError
from securitylab.projects import add_project
from securitylab.snapshots import (create_snapshot, verify_snapshot, list_snapshots,
                                   MAX_FILE_BYTES)
from securitylab.profile_plan import plan_snapshot
from securitylab.storage import Store


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        self.state = self.base / 'state'
        self.store = Store(self.state)
        self.addCleanup(self.store.close)

    def put(self, name, value):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding='utf-8')
        return path

    def create(self):
        project = add_project(self.store, self.source, 'Fixture Project')
        return create_snapshot(self.store, project['id']), project['id']

    def test_content_hashes_original_unchanged_and_stable_copy(self):
        p = self.put('src/api.py', 'hello=123')
        result, pid = self.create()
        self.assertEqual(result['file_count'], 1)
        self.assertEqual(result['status'], 'CREATED_UNVERIFIED')
        self.assertEqual(verify_snapshot(self.store, result['snapshot_id'])['status'], 'VERIFIED_CONTENT_HASHES')
        self.assertEqual((Path(result['workspace']) / 'src/api.py').read_text(), 'hello=123')
        p.write_text('modified later', encoding='utf-8')
        self.assertEqual((Path(result['workspace']) / 'src/api.py').read_text(), 'hello=123')
        self.assertEqual(len(list_snapshots(self.store, pid)), 1)
        self.assertFalse((self.source / '.securitylab').exists())

    def test_windows_cached_direntry_zero_identity_is_not_a_false_change(self):
        """Reproduce Windows Python 3.13 DirEntry.stat st_dev/st_ino=0."""
        self.put('src/api.py', 'answer = 42')
        real_scandir = os.scandir

        class WindowsLikeEntry:
            def __init__(self, raw):
                self.raw = raw
                self.name, self.path = raw.name, raw.path

            def stat(self, *, follow_symlinks=True):
                original = self.raw.stat(follow_symlinks=follow_symlinks)
                if follow_symlinks:
                    return original
                return SimpleNamespace(
                    st_mode=original.st_mode, st_size=original.st_size,
                    st_mtime_ns=original.st_mtime_ns, st_dev=0, st_ino=0,
                    st_file_attributes=getattr(original, 'st_file_attributes', 0),
                )

        class WindowsLikeScandir:
            def __init__(self, path):
                self.real = real_scandir(path)

            def __enter__(self):
                self.real.__enter__()
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return self.real.__exit__(exc_type, exc_value, traceback)

            def __iter__(self):
                for entry in self.real:
                    yield WindowsLikeEntry(entry)

        # Both the walk and subsequent verifier compare Windows-like cached
        # listing metadata with real lstat/fstat handle metadata.
        with patch('os.scandir', side_effect=WindowsLikeScandir):
            result, _ = self.create()
            check = verify_snapshot(self.store, result['snapshot_id'])
        self.assertEqual(check['status'], 'VERIFIED_CONTENT_HASHES')

    def test_source_replaced_after_directory_listing_fails_closed(self):
        from securitylab.snapshots import _fresh_regular
        original = self.put('code.py', 'original')
        listing = original.lstat()
        original.unlink()
        original.write_text('changed-different-size', encoding='utf-8')
        with self.assertRaisesRegex(PolicyError, 'changed between enumeration'):
            _fresh_regular(original, listing, 'Source')

    def test_skips_common_secret_files_and_excluded_directories(self):
        self.put('app/main.py', 'pass')
        self.put('.env', 'PASSWORD=private')
        self.put('config/.npmrc', '_authToken=private')
        self.put('test.pem', 'secret material')
        self.put('node_modules/index.js', 'dependency')
        result, _ = self.create()
        self.assertEqual(result['file_count'], 1)
        self.assertEqual(result['skipped_possible_secret_files'], 3)
        workspace = Path(result['workspace'])
        self.assertEqual(list(workspace.rglob('*')), [workspace / 'app', workspace / 'app/main.py'])
        contents = Path(result['manifest']).read_text()
        self.assertNotIn('private', contents)
        self.assertNotIn('test.pem', contents)
        self.assertNotIn('.npmrc', contents)

    def test_mutation_in_workspace_fails_verification_even_if_same_length(self):
        self.put('x.py', 'aaaa')
        result, _ = self.create()
        (Path(result['workspace']) / 'x.py').write_text('bbbb')
        with self.assertRaisesRegex(PolicyError, 'checksum mismatch'):
            verify_snapshot(self.store, result['snapshot_id'])

    def test_mutated_manifest_fails(self):
        self.put('app.py', 'pass')
        result, _ = self.create()
        Path(result['manifest']).write_text('{}')
        with self.assertRaisesRegex(PolicyError, 'manifest checksum'):
            verify_snapshot(self.store, result['snapshot_id'])

    def test_added_file_and_missing_file_fail(self):
        self.put('app.py', 'pass')
        result, _ = self.create()
        workspace = Path(result['workspace'])
        (workspace / 'extra.txt').write_text('untracked')
        with self.assertRaisesRegex(PolicyError, 'extra'):
            verify_snapshot(self.store, result['snapshot_id'])
        (workspace / 'extra.txt').unlink()
        (workspace / 'app.py').unlink()
        with self.assertRaisesRegex(PolicyError, 'missing'):
            verify_snapshot(self.store, result['snapshot_id'])

    def test_unexpected_empty_directory_fails_verification(self):
        self.put('app.py', 'pass')
        result, _ = self.create()
        (Path(result['workspace']) / 'extra_directory').mkdir()
        with self.assertRaisesRegex(PolicyError, 'extra directory'):
            verify_snapshot(self.store, result['snapshot_id'])

    def test_plan_is_inert_and_has_more_than_one_service(self):
        self.put('backend/pyproject.toml', '[project]\nname="api"\n')
        self.put('frontend/package.json', json.dumps({'scripts': {'start': 'DANGEROUS'}}))
        result, _ = self.create()
        plan = plan_snapshot(self.store, result['snapshot_id'])
        self.assertEqual([x['detected_profile'] for x in plan['services']], ['python', 'node'])
        self.assertTrue(plan['multi_service'])
        self.assertEqual(plan['execution_permission'], 'DENIED')
        self.assertTrue(all(x['start'] == 'DISABLED' for x in plan['services']))
        self.assertNotIn('DANGEROUS', json.dumps(plan))

    def test_big_file_policy_cleans_temp_and_does_not_register(self):
        self.put('big.dat', 'x' * (MAX_FILE_BYTES + 1))
        project = add_project(self.store, self.source)
        with self.assertRaisesRegex(PolicyError, 'limit exceeded'):
            create_snapshot(self.store, project['id'])
        self.assertEqual(list_snapshots(self.store, project['id']), [])
        self.assertEqual(list((self.state / 'snapshots').iterdir()), [])

    def test_symlink_to_outside_not_copied(self):
        outside = self.base / 'outside'
        outside.write_text('PRIVATE')
        try:
            (self.source / 'link.txt').symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest('Symlinks not available')
        result, _ = self.create()
        self.assertEqual(result['file_count'], 0)
        self.assertEqual(verify_snapshot(self.store, result['snapshot_id'])['file_count'], 0)

    def test_symlink_in_workspace_fails_verification(self):
        self.put('ok.py', 'pass')
        result, _ = self.create()
        workspace = Path(result['workspace'])
        outside = self.base / 'secret'
        outside.write_text('SECRET')
        try:
            (workspace / 'link').symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest('Symlinks not available')
        with self.assertRaisesRegex(PolicyError, 'link'):
            verify_snapshot(self.store, result['snapshot_id'])

    def test_change_during_copy_rejects_snapshot(self):
        self.put('app.py', 'initial')
        project = add_project(self.store, self.source)
        from securitylab import snapshots as module
        copy_original = module._copy_regular
        def mutate(source, target, observed, remaining):
            answer = copy_original(source, target, observed, remaining)
            source.write_text('modified-more', encoding='utf-8')
            return answer
        with patch('securitylab.snapshots._copy_regular', side_effect=mutate):
            with self.assertRaisesRegex(PolicyError, 'metadata changed'):
                create_snapshot(self.store, project['id'])
        self.assertEqual(list_snapshots(self.store, project['id']), [])
        self.assertEqual(list((self.state / 'snapshots').iterdir()), [])

    def test_source_inside_state_rejected(self):
        another = self.state / 'nested'
        another.mkdir()
        project = add_project(self.store, another)
        with self.assertRaisesRegex(PolicyError, 'nested inside'):
            create_snapshot(self.store, project['id'])

    def test_invalid_id_fails_and_not_path_traversal(self):
        with self.assertRaises(PolicyError):
            create_snapshot(self.store, '../foo')
        with self.assertRaises(PolicyError):
            verify_snapshot(self.store, '../../etc')

    def test_restart_and_sqlite_snapshot_persistence(self):
        self.put('x.py', 'pass')
        result, pid = self.create()
        self.store.close()
        self.store = Store(self.state)
        self.assertEqual(list_snapshots(self.store, pid)[0]['id'], result['snapshot_id'])
        self.assertEqual(verify_snapshot(self.store, result['snapshot_id'])['status'], 'VERIFIED_CONTENT_HASHES')

    def test_cli_snapshot_verify_plan_and_scan_is_still_blocked(self):
        self.put('app/pyproject.toml', '[project]\nname="x"\n')
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = main(['--state', str(self.state), 'repo', 'add', str(self.source)])
        self.assertEqual(rc, 0)
        pid = json.loads(stdout.getvalue())['id']
        def command(*args):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(['--state', str(self.state), 'repo', *args]), 0)
            return json.loads(out.getvalue())
        sid = command('snapshot', pid)['snapshot_id']
        self.assertEqual(command('verify-snapshot', sid)['status'], 'VERIFIED_CONTENT_HASHES')
        self.assertEqual(command('plan', sid)['execution_permission'], 'DENIED')
        self.assertEqual(command('snapshots', pid)[0]['id'], sid)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['scan', str(self.source)]), 2)

if __name__ == '__main__':
    unittest.main()
