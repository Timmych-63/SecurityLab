"""Resumable deterministic demonstration, separate from future AI automation."""
from pathlib import Path
from .fixture import VULNERABLE, FIXED, REGRESSION
from .gitops import DemoGit
from .policy import Limits, PolicyError, safe_path, run_id
from .runner import FixtureRunner
from .storage import Store, atomic_text, worker_lock
from .validator import confirmed, validate

class Orchestrator:
    def __init__(self, store: Store, limits=Limits(), docker_broker_factory=None):
        self.docker_broker_factory = docker_broker_factory
        self.store = store
        self.limits = limits
        self.runner = FixtureRunner(limits)

    def repo(self, rid):
        return safe_path(self.store.root, f'runs/{run_id(rid)}/repo')

    def initialise_fixture(self, repo):
        repo.mkdir(parents=True, exist_ok=True)
        git = DemoGit(repo)
        if not (repo / '.git').exists():
            git.call('init', '-b', 'main')
        # Initialisation can resume after a crash before the first commit.
        if not (repo / '.git/refs/heads/main').exists():
            atomic_text(safe_path(repo, 'service.py'), VULNERABLE)
            atomic_text(safe_path(repo, '.gitignore'), '__pycache__/\n*.pyc\n')
            git.commit(['service.py', '.gitignore'], 'demo: baseline synthetic access defect')
        if git.call('branch', '--show-current') != 'main' or not git.clean():
            raise PolicyError('Baseline repository changed')
        self.runner.check_source(repo, VULNERABLE)
        return git

    def patch(self, repo, rid):
        git = DemoGit(repo)
        branch = 'securitylab/' + rid[:12]
        current = git.call('branch', '--show-current')
        if current == 'main':
            git.call('checkout', '-b', branch)
        elif current != branch:
            raise PolicyError('Unexpected branch')
        source = safe_path(repo, 'service.py')
        if source.read_bytes() not in {VULNERABLE.encode(), FIXED.encode()}:
            raise PolicyError('Unexpected source change')
        # Idempotent, exact-path writes allow restart after partial patch/commit.
        atomic_text(source, FIXED)
        atomic_text(safe_path(repo, 'test_regression.py'), REGRESSION)
        git.commit(['service.py', 'test_regression.py'], 'fix: enforce synthetic record ownership; add regression')
        if not git.clean():
            raise PolicyError('Unexpected uncommitted files')
        return git

    def rollback(self, rid):
        """Revert only this generated demo fix; preserve both Git history and main."""
        with worker_lock(self.store.root):
            row = self.store.get(rid)
            if row['status'] == 'ROLLED_BACK':
                return row
            if row['status'] != 'DONE':
                raise PolicyError('Only a completed demo can be rolled back')
            repo = self.repo(rid)
            git = DemoGit(repo)
            if not git.clean() or git.call('branch', '--show-current') != 'securitylab/' + rid[:12]:
                raise PolicyError('Rollback requires the clean generated branch')
            patch = self.store.evidence(rid)['patch']['revision']
            head = git.head()
            if head == patch:
                git.call('revert', '--no-edit', patch)
            elif git.call('rev-parse', 'HEAD^') != patch or git.call('diff', 'main', 'HEAD', '--'):
                raise PolicyError('Unexpected changes after patch; rollback denied')
            self.runner.check_source(repo, VULNERABLE)
            finding = self.store.finding(rid) | {'status': 'REOPENED_AFTER_ROLLBACK'}
            import json
            with self.store.db:
                self.store.db.execute("UPDATE runs SET status='ROLLED_BACK' WHERE id=?", (rid,))
                self.store.db.execute('UPDATE findings SET body=? WHERE run_id=?', (json.dumps(finding), rid))
                self.store.event(rid, 'rolled_back', {'revision': git.head(), 'reverted': patch})
            self.store.export_events(rid, self.store.root / 'runs' / rid / 'events.jsonl')
            return self.store.get(rid)

    def run(self, rid, after_stage=None):
        """after_stage is an in-process test hook, never exposed to repository data."""
        with worker_lock(self.store.root):
            if not self.store.begin(rid, self.limits.max_attempts):
                return self.store.get(rid)
            try:
                mode = self.store.get(rid)['mode']
                if mode == 'scripted-demo-docker-no-ai':
                    from .docker_fixture import DockerFixtureRunner
                    broker = self.docker_broker_factory() if self.docker_broker_factory else None
                    self.runner = DockerFixtureRunner(rid, self.store.root / 'runs' / rid / 'receipts', self.limits, broker)
                elif mode == 'scripted-demo-no-ai':
                    self.runner = FixtureRunner(self.limits)
                else:
                    raise PolicyError('Unknown stored execution mode')
                while True:
                    row = self.store.get(rid)
                    if row['stop']:
                        self.store.pause(rid, 'STOPPED', 'Stopped by operator')
                        break
                    stage = row['stage']
                    repo = self.repo(rid)
                    stop = lambda: bool(self.store.get(rid)['stop'])
                    if stage == 'QUEUED':
                        self.initialise_fixture(repo)
                        finding = dict(id='DEMO-ACCESS-001', title='Cross-user record access',
                            service='synthetic-records', file='service.py', line=4,
                            description='Authenticated user can read another owner record',
                            cause='Missing ownership check', severity='HIGH',
                            reproduction='alice reads record two owned by bob',
                            expected=[403, None], actual=[200, 'synthetic-B'],
                            recommendation='Check owner before returning value',
                            status='HYPOTHESIS', mode=mode)
                        self.store.advance(rid, stage, 'DISCOVERED', finding=finding)
                    elif stage == 'DISCOVERED':
                        git = DemoGit(repo)
                        baseline = self.runner.suite(repo, git.head(), False, stop, kind='baseline')
                        if not confirmed(baseline):
                            raise PolicyError('Baseline proof failed; cannot confirm')
                        finding = self.store.finding(rid) | {'status': 'CONFIRMED'}
                        self.store.advance(rid, stage, 'CONFIRMED', {'baseline': baseline}, finding)
                    elif stage == 'CONFIRMED':
                        git = self.patch(repo, rid)
                        self.store.advance(rid, stage, 'PATCHED', {'patch': {
                            'revision': git.head(), 'branch': git.call('branch', '--show-current'),
                            'diff': git.call('diff', 'main..HEAD', '--', 'service.py', 'test_regression.py')}},
                            self.store.finding(rid) | {'status': 'FIX_PENDING_VERIFICATION'})
                    elif stage == 'PATCHED':
                        git = DemoGit(repo)
                        revision = git.head()
                        evidence = {'regression': self.runner.regression(repo, revision, stop),
                                    'build': self.runner.build(repo, revision, stop),
                                    'mandatory': self.runner.suite(repo, revision, True, stop, kind='mandatory'),
                                    'recheck': self.runner.suite(repo, revision, True, stop, kind='recheck')}
                        self.store.advance(rid, stage, 'VERIFIED', evidence)
                    elif stage == 'VERIFIED':
                        git = DemoGit(repo)
                        self.runner.check_source(repo, FIXED)
                        verdict = validate(self.store.evidence(rid), git.head(), git.clean(), git.call('rev-parse', 'main'))
                        receipt_errors = self.runner.audit(self.store.evidence(rid))
                        if receipt_errors:
                            verdict['status'] = 'NEEDS_REVIEW'
                            verdict['reasons'].extend(receipt_errors)
                        verdict['executor'] = 'docker' if mode == 'scripted-demo-docker-no-ai' else 'local'
                        self.store.advance(rid, stage, 'DONE', {'verdict': verdict},
                            self.store.finding(rid) | {'status': verdict['status']})
                    elif stage == 'DONE':
                        break
                    if after_stage:
                        after_stage(self.store.get(rid)['stage'])
            except KeyboardInterrupt:
                self.store.pause(rid, 'STOPPED', 'Interrupted by operator')
                raise
            except (PolicyError, OSError, ValueError) as e:
                status = 'STOPPED' if self.store.get(rid)['stop'] else 'BLOCKED'
                self.store.pause(rid, status, str(e))
            finally:
                self.store.export_events(rid, self.store.root / 'runs' / rid / 'events.jsonl')
        return self.store.get(rid)
