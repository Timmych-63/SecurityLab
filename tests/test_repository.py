"""S6.1: read-only multi-repository discovery, negative safety cases."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from securitylab.cli import main
from securitylab.policy import PolicyError
from securitylab.projects import add_project, assert_state_outside_project, list_projects, project_detail
from securitylab.repository import PROFILES, inventory_repository
from securitylab.storage import Store


class RepoFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.repo = self.home / 'repo'
        self.repo.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, text):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path


class RepositoryInventoryTests(RepoFixture, unittest.TestCase):
    def test_python_repository(self):
        self.write('pyproject.toml', '[project]\nname="example"\ndependencies=["fastapi>=0.1"]\n')
        self.write('src/main.py', 'print("hello")')
        self.write('tests/test_api.py', 'def test_basic(): pass')
        inv = inventory_repository(self.repo)
        self.assertEqual(inv['mode'], 'READ_ONLY_INVENTORY')
        self.assertEqual(inv['languages']['python'], 2)
        self.assertEqual(inv['test_file_count'], 1)
        self.assertEqual(inv['services'][0]['detected_profile'], 'python')
        self.assertEqual(inv['services'][0]['framework_hints'], ['fastapi'])
        self.assertEqual(inv['execution_permission'], 'DENIED')
        self.assertFalse((self.repo / '.securitylab').exists())

    def test_node_repository_only_script_names_not_bodies(self):
        dangerous = 'touch /tmp/should-not-execute'
        self.write('package.json', json.dumps({'scripts': {'test': dangerous}, 'dependencies': {'express': '4'}}))
        self.write('src/app.ts', '// harmless')
        inv = inventory_repository(self.repo)
        self.assertEqual(inv['services'][0]['detected_profile'], 'node')
        self.assertEqual(inv['services'][0]['script_names'], ['test'])
        self.assertEqual(inv['services'][0]['framework_hints'], ['express'])
        self.assertNotIn(dangerous, json.dumps(inv))
        self.assertFalse(Path('/tmp/should-not-execute').exists())

    def test_multi_service_project(self):
        self.write('backend/pyproject.toml', '[project]\nname="api"\n')
        self.write('frontend/package.json', '{"scripts":{"build":"echo hi"}}')
        self.assertEqual([(x['directory'], x['detected_profile']) for x in inventory_repository(self.repo)['services']],
                         [('backend', 'python'), ('frontend', 'node')])

    def test_other_stacks_are_detected_but_not_executable(self):
        self.write('go.mod', 'module test.local/x\n\ngo 1.22\n')
        self.write('Cargo.toml', '[package]\nname="demo"\nversion="0.1.0"')
        inv = inventory_repository(self.repo)
        self.assertEqual({x['detected_profile'] for x in inv['services']}, {'go', 'rust'})
        self.assertTrue(all(x['execution'] == 'DISABLED' for x in inv['services']))
        self.assertTrue(all(x['execution'] == 'NOT_IMPLEMENTED' for x in PROFILES))

    def test_symlink_out_of_repo_skipped(self):
        outside = self.home / 'private.py'
        outside.write_text('top secret', encoding='utf-8')
        try:
            (self.repo / 'alias.py').symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest('No symlink creation permission')
        inv = inventory_repository(self.repo)
        self.assertEqual(inv['file_count'], 0)
        self.assertEqual(inv['skipped_link_count'], 1)
        self.assertNotIn('top secret', json.dumps(inv))
        with self.assertRaises(PolicyError):
            inventory_repository(self.repo / 'alias.py')

    def test_directory_symlink_not_followed(self):
        outside = self.home / 'private'
        outside.mkdir()
        (outside / 'package.json').write_text('{}', encoding='utf-8')
        try:
            (self.repo / 'private').symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('No symlink creation permission')
        inv = inventory_repository(self.repo)
        self.assertEqual(inv['services'], [])
        self.assertEqual(inv['skipped_link_count'], 1)

    def test_secrets_never_parsed(self):
        self.write('.env', 'API_KEY=do-not-expose')
        self.write('cert.pem', 'PRIVATE-MATERIAL')
        inv = inventory_repository(self.repo)
        self.assertEqual(inv['possible_secret_file_count'], 2)
        self.assertNotIn('do-not-expose', json.dumps(inv))
        self.assertNotIn('PRIVATE-MATERIAL', json.dumps(inv))

    def test_exclusions_avoid_dependency_trees(self):
        self.write('node_modules/dep/package.json', '{}')
        self.write('dist/bundle.js', 'alert(1)')
        self.write('.git/config', 'some secret')
        inv = inventory_repository(self.repo)
        self.assertEqual(inv['file_count'], 0)
        self.assertEqual(inv['ignored_directory_count'], 3)

    def test_invalid_manifest_safe_diagnostic(self):
        self.write('package.json', 'not json {')
        inv = inventory_repository(self.repo)
        self.assertEqual(inv['services'][0]['detected_profile'], 'node')
        self.assertIn('Manifest unreadable/invalid', ' '.join(inv['notes']))

    def test_oversize_manifest_not_read(self):
        self.write('package.json', 'x' * 150000)
        inv = inventory_repository(self.repo)
        self.assertEqual(inv['services'][0]['script_names'], [])
        self.assertIn('over limit', ' '.join(inv['notes']))

    def test_fingerprint_changes_on_source_modification(self):
        path = self.write('src/app.py', 'a')
        old = inventory_repository(self.repo)
        path.write_text('different content', encoding='utf-8')
        new = inventory_repository(self.repo)
        self.assertNotEqual(old['metadata_fingerprint'], new['metadata_fingerprint'])
        self.assertNotIn('different content', json.dumps(new))

    def test_inventory_stable_for_unchanged_tree(self):
        self.write('z/module.py', 'pass')
        self.write('a/package.json', '{}')
        a = inventory_repository(self.repo)
        b = inventory_repository(self.repo)
        self.assertEqual(a, b)

    def test_file_count_limit_fail_closed(self):
        self.write('a.py', 'pass')
        self.write('b.py', 'pass')
        with patch('securitylab.repository.MAX_FILES', 1), self.assertRaises(PolicyError):
            inventory_repository(self.repo)

    def test_total_entry_limit_fail_closed(self):
        self.write('a.py', 'pass')
        self.write('b.py', 'pass')
        with patch('securitylab.repository.MAX_ENTRIES', 1), self.assertRaises(PolicyError):
            inventory_repository(self.repo)

    def test_depth_limit_fail_closed(self):
        self.write('deep/nested/module.py', 'pass')
        with patch('securitylab.repository.MAX_DEPTH', 1), self.assertRaises(PolicyError):
            inventory_repository(self.repo)

    def test_unreadable_or_missing_root(self):
        with self.assertRaises(PolicyError):
            inventory_repository(self.home / 'missing')
        self.write('file.py', 'pass')
        with self.assertRaises(PolicyError):
            inventory_repository(self.repo / 'file.py')

    def test_special_fifo_not_read(self):
        if not hasattr(os, 'mkfifo'):
            self.skipTest('No FIFO support')
        os.mkfifo(self.repo / 'blocking')
        inv = inventory_repository(self.repo)
        self.assertEqual(inv['skipped_special_count'], 1)


class RepositoryRegistryTests(RepoFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.state = self.home / 'state'

    def test_register_show_list_stale(self):
        self.write('package.json', '{"name":"example"}')
        store = Store(self.state)
        try:
            item = add_project(store, self.repo, 'My Node App')
            self.assertEqual(item['status'], 'REGISTERED_INVENTORY_ONLY')
            self.assertEqual(len(list_projects(store)), 1)
            self.assertEqual(project_detail(store, item['id'])['source_status'], 'UNCHANGED_METADATA')
            self.write('src/index.ts', 'new contents')
            self.assertEqual(project_detail(store, item['id'])['source_status'], 'CHANGED_METADATA')
            self.assertFalse((self.repo / '.securitylab').exists())
        finally:
            store.close()
        reopened = Store(self.state)
        try:
            self.assertEqual(len(list_projects(reopened)), 1)
        finally:
            reopened.close()

    def test_library_registration_also_rejects_embedded_state(self):
        with StoreContext(self.repo / '.securitylab') as store:
            with self.assertRaises(PolicyError):
                add_project(store, self.repo)
            self.assertEqual(list_projects(store), [])

    def test_state_inside_source_blocked_before_store_created(self):
        with self.assertRaises(PolicyError):
            assert_state_outside_project(self.repo / '.securitylab', self.repo)
        self.assertFalse((self.repo / '.securitylab').exists())

    def test_invalid_project_name_and_id(self):
        with StoreContext(self.state) as store:
            with self.assertRaises(PolicyError):
                add_project(store, self.repo, 'a\n b')
            with self.assertRaises(PolicyError):
                project_detail(store, '../../etc')
            self.assertEqual(list_projects(store), [])

    def test_cli_commands_and_scan_remains_blocked(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(['repo', 'inspect', str(self.repo)])
        self.assertEqual(code, 0, stderr.getvalue())
        self.assertEqual(json.loads(stdout.getvalue())['scan_permission'], 'DENIED')

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(['--state', str(self.repo / '.securitylab'), 'repo', 'add', str(self.repo)])
        self.assertEqual(code, 2)
        self.assertFalse((self.repo / '.securitylab').exists())

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(['--state', str(self.state), 'repo', 'add', str(self.repo), '--name', 'Demo'])
        self.assertEqual(code, 0, stderr.getvalue())
        result = json.loads(stdout.getvalue())
        self.assertEqual(result['name'], 'Demo')

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(['--state', str(self.state), 'repo', 'show', result['id']])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout.getvalue())['source_status'], 'UNCHANGED_METADATA')

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main(['--state', str(self.state), 'repo', 'list']), 0)
        self.assertEqual(len(json.loads(stdout.getvalue())), 1)

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['scan', str(self.repo)]), 2)


class StoreContext:
    def __init__(self, path): self.path = path
    def __enter__(self):
        self.store = Store(self.path)
        return self.store
    def __exit__(self, *args): self.store.close()


if __name__ == '__main__':
    unittest.main()
