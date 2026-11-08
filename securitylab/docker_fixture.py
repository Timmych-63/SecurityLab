"""S3: approved synthetic fixtures via S2, with host-side receipt verification.

This does NOT accept arbitrary model-generated source as trusted test evidence.
"""
import hashlib
import json
from pathlib import Path
import re
from .container_runner import DockerBroker
from .fixture import VULNERABLE, FIXED, SUITE, REGRESSION, digest
from .job_contract import job_bytes
from .policy import Limits, PolicyError, safe_path, run_id
from .runner import FixtureRunner

KINDS = ('baseline', 'regression', 'build', 'mandatory', 'recheck')
REGRESSION_TASK = '''import unittest, sys
suite = unittest.defaultTestLoader.loadTestsFromName("test_regression")
result = unittest.TextTestRunner().run(suite)
sys.exit(0 if result.wasSuccessful() and result.testsRun == 2 else 1)
'''
BUILD_TASK = '''from pathlib import Path
compile(Path("service.py").read_text(encoding="utf-8"), "service.py", "exec")
'''
SUITE_TASK = 'import sys\nsys.argv = ["protected-suite", "/work/service.py"]\n' + SUITE


def recipe(kind):
    if kind not in KINDS:
        raise PolicyError('Unknown proof kind')
    source = VULNERABLE if kind == 'baseline' else FIXED
    files = {'service.py': source}
    if kind == 'regression':
        files.update({'task.py': REGRESSION_TASK, 'test_regression.py': REGRESSION})
        test_hash = digest(REGRESSION)
    elif kind == 'build':
        files['task.py'] = BUILD_TASK
        test_hash = digest(BUILD_TASK)
    else:
        files['task.py'] = SUITE_TASK
        test_hash = digest(SUITE)
    return source, test_hash, job_bytes(files)


def read_receipt(directory, receipt_id):
    path = safe_path(directory, run_id(receipt_id) + '.json')
    with path.open('rb') as f:
        raw = f.read(1048577)
    if len(raw) > 1048576:
        raise PolicyError('Oversized receipt')
    parsed = json.loads(raw.decode('utf-8'))
    if not isinstance(parsed, dict):
        raise PolicyError('Invalid receipt')
    return parsed, hashlib.sha256(raw).hexdigest()


class DockerFixtureRunner(FixtureRunner):
    def __init__(self, rid, directory: Path, limits=Limits(), broker=None):
        super().__init__(limits)
        self.rid = run_id(rid)
        self.directory = directory
        self.broker = broker if broker is not None else DockerBroker(Path.cwd())

    def _proof(self, repo, revision, kind, stop):
        source, test_hash, payload = recipe(kind)
        self.check_source(repo, source)
        if kind == 'regression' and safe_path(repo, 'test_regression.py').read_bytes() != REGRESSION.encode():
            raise PolicyError('Modified regression test')
        if not re.fullmatch(r'[a-f0-9]{40,64}', revision):
            raise PolicyError('Invalid Git revision')
        binding = {'run_id': self.rid, 'kind': kind, 'revision': revision,
                   'source_hash': digest(source), 'test_hash': test_hash}
        record = self.broker.run(payload, self.directory, self.limits, binding=binding, stop=stop)
        # Read the independently persisted host record, not a claim from stdout.
        persisted, receipt_hash = read_receipt(self.directory, record['id'])
        if record != persisted:
            raise PolicyError('Broker return differs from saved receipt')
        if persisted.get('status') == 'CANCELLED' and not stop():
            raise KeyboardInterrupt
        result = persisted.get('execution', {})
        proof = dict(result=result, revision=revision, source_hash=digest(source), test_hash=test_hash,
                     executor='docker', run_id=self.rid, kind=kind,
                     receipt_id=record['id'], receipt_sha256=receipt_hash)
        errors = self.audit_one(proof, kind)
        if errors:
            raise PolicyError('; '.join(errors))
        if kind in ('baseline', 'mandatory', 'recheck'):
            try:
                parsed = json.loads(result['stdout'])
                if (not isinstance(parsed, dict) or set(parsed) != {'checks', 'observed'}
                    or not isinstance(parsed['checks'], dict) or not isinstance(parsed['observed'], list)):
                    raise ValueError('Unexpected result shape')
                proof.update(checks=parsed['checks'], observed=parsed['observed'])
            except (ValueError, KeyError, TypeError) as e:
                raise PolicyError('Protected suite did not return the expected result') from e
        return proof

    def suite(self, repo, revision, fixed, stop=lambda: False, kind=None):
        kind = kind or ('mandatory' if fixed else 'baseline')
        if kind not in ('baseline','mandatory','recheck') or fixed != (kind != 'baseline'):
            raise PolicyError('Incorrect suite purpose')
        return self._proof(repo, revision, kind, stop)

    def regression(self, repo, revision, stop=lambda: False):
        return self._proof(repo, revision, 'regression', stop)

    def build(self, repo, revision, stop=lambda: False):
        return self._proof(repo, revision, 'build', stop)

    def audit_one(self, e, kind):
        try:
            source, test_hash, payload = recipe(kind)
            expected_binding = {'run_id': self.rid, 'kind': kind, 'revision': e['revision'],
                                'source_hash': digest(source), 'test_hash': test_hash}
            if e.get('executor') != 'docker' or any(e.get(k) != v for k,v in expected_binding.items()):
                raise PolicyError('Proof binding mismatch')
            receipt, h = read_receipt(self.directory, e['receipt_id'])
            if h != e['receipt_sha256'] or receipt.get('id') != e['receipt_id']:
                raise PolicyError('Receipt digest/ID mismatch')
            if receipt.get('binding') != expected_binding:
                raise PolicyError('Receipt belongs to another run, check or revision')
            if receipt.get('payload_sha256') != hashlib.sha256(payload).hexdigest():
                raise PolicyError('Receipt payload does not match protected fixture/test')
            if receipt.get('cleanup') != 'PASS' or receipt.get('status') not in {'COMPLETED','NONZERO_EXIT'}:
                raise PolicyError('Execution interrupted, blocked or not cleaned up')
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', receipt.get('image_id','')):
                raise PolicyError('Missing immutable image ID')
            execution = receipt['execution']
            state = receipt['container_state']
            code = execution['returncode']
            if (execution != e['result'] or type(code) is not int or state.get('ExitCode') != code
                or state.get('Running') is not False or state.get('OOMKilled') is not False or state.get('Error')
                or any(execution.get(x) is not False for x in ('timed_out','cancelled','truncated'))):
                raise PolicyError('Result/daemon status mismatch or incomplete execution')
            expected_status = 'COMPLETED' if code == 0 else 'NONZERO_EXIT'
            if receipt['status'] != expected_status:
                raise PolicyError('Incorrect completion status')
            if kind in ('baseline','mandatory','recheck') and 'checks' in e:
                parsed = json.loads(execution['stdout'])
                if parsed != {'checks':e['checks'], 'observed':e['observed']}:
                    raise PolicyError('Parsed evidence differs from protected suite output')
            return []
        except (PolicyError, OSError, ValueError, KeyError, TypeError) as exc:
            return [f'{kind}: {exc}']

    def audit(self, evidence):
        errors = []
        ids = []
        for kind in KINDS:
            e = evidence.get(kind, {})
            if not isinstance(e, dict):
                e = {}
            errors.extend(self.audit_one(e, kind))
            ids.append(e.get('receipt_id') if isinstance(e.get('receipt_id'), str) else None)
        if len(set(ids)) != len(KINDS):
            errors.append('Each verification requires a distinct receipt')
        return errors
