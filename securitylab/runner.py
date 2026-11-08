import json
from pathlib import Path
import sys
from .fixture import VULNERABLE, FIXED, SUITE, REGRESSION, digest
from .policy import PolicyError, Limits, safe_path
from .process import execute

class FixtureRunner:
    """Local execution is restricted to byte-identical reviewed fixtures."""
    def __init__(self, limits=Limits()):
        self.limits = limits

    def check_source(self, repo: Path, expected: str):
        path = safe_path(repo, 'service.py')
        if path.read_bytes() != expected.encode():
            raise PolicyError('Untrusted source: host execution denied')
        return path

    def suite(self, repo, revision, fixed, stop=lambda: False, kind=None):
        source = FIXED if fixed else VULNERABLE
        path = self.check_source(repo, source)
        result = execute([sys.executable, '-I', '-B', '-c', SUITE, str(path)], repo, self.limits, stop)
        try:
            output = json.loads(result.stdout)
        except ValueError:
            output = {}
        return dict(result=result.data(), revision=revision, source_hash=digest(source),
                    test_hash=digest(SUITE), checks=output.get('checks', {}), observed=output.get('observed'))

    def regression(self, repo, revision, stop=lambda: False):
        source = self.check_source(repo, FIXED)
        test = safe_path(repo, 'test_regression.py')
        if test.read_bytes() != REGRESSION.encode():
            raise PolicyError('Modified regression test')
        # -I prevents importing modules from arbitrary cwd or PYTHONPATH.
        program = ('import sys; sys.path.insert(0, sys.argv[1]); '
                   'import unittest; suite=unittest.defaultTestLoader.loadTestsFromName("test_regression"); '
                   'result=unittest.TextTestRunner().run(suite); '
                   'sys.exit(0 if result.wasSuccessful() and result.testsRun==2 else 1)')
        result = execute([sys.executable, '-I', '-B', '-c', program, str(repo)], repo, self.limits, stop)
        return dict(result=result.data(), revision=revision, source_hash=digest(FIXED), test_hash=digest(REGRESSION))

    def build(self, repo, revision, stop=lambda: False):
        path = self.check_source(repo, FIXED)
        result = execute([sys.executable, '-I', '-B', '-c',
                          'import pathlib,sys; compile(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"),"service.py","exec")',
                          str(path)], repo, self.limits, stop)
        return dict(result=result.data(), revision=revision, source_hash=digest(FIXED))

    def audit(self, evidence):
        return []  # Local mode is restricted to byte-identical built-in fixtures.
