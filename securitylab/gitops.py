"""Git operations are scoped to the generated demo repository; never merge/push."""
import os
from pathlib import Path
from .policy import PolicyError, Limits
from .process import execute

class DemoGit:
    def __init__(self, path: Path):
        self.path = path
        if path.is_symlink():
            raise PolicyError("Symlink repository")

    def call(self, *args):
        env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_TERMINAL_PROMPT='0', GIT_AUTHOR_NAME='SecurityLab Demo',
                   GIT_AUTHOR_EMAIL='demo@localhost', GIT_COMMITTER_NAME='SecurityLab Demo',
                   GIT_COMMITTER_EMAIL='demo@localhost')
        result = execute(['git', '-c', 'core.hooksPath=' + os.devnull,
                          '-c', 'commit.gpgsign=false', *args], self.path, Limits(), env=env)
        if not result.passed:
            raise PolicyError('Git failed: ' + result.stderr[:1000])
        return result.stdout.strip()

    def head(self):
        return self.call('rev-parse', 'HEAD')

    def clean(self):
        return not self.call('status', '--porcelain', '--untracked-files=all')

    def commit(self, files, message):
        if any(f not in {'service.py', 'test_regression.py', '.gitignore'} for f in files):
            raise PolicyError('Patch path not allowed')
        self.call('add', '--', *files)
        if self.call('diff', '--cached', '--name-only'):
            self.call('commit', '-m', message)
        return self.head()
