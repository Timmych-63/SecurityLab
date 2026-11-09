"""Actual bounded Blue source executed in Docker; verdict computed on host."""
import hashlib
import json
from pathlib import Path
import uuid
from .candidate_policy import validate_candidate
from .container_runner import DockerBroker, IMAGE_ID
from .docker_fixture import read_receipt
from .fixture import VULNERABLE, digest
from .job_contract import job_bytes
from .policy import Limits, PolicyError
from .storage import atomic_text

# Author-defined expectations, not generated or editable by Blue.
CASES = [(u, r) for u in (None, 'alice', 'bob', 'attacker', '')
         for r in ('one', 'two', 'missing')]
TASK = ('import json\nfrom service import read_record\n'
        + 'cases = ' + repr(CASES) + '\n'
        + 'print(json.dumps([read_record(u, r) for u, r in cases]))\n')


def expected(fixed):
    result = []
    for user, rid in CASES:
        if user is None:
            value = [401, None]
        elif rid == 'missing':
            value = [404, None]
        elif fixed and user != {'one': 'alice', 'two': 'bob'}[rid]:
            value = [403, None]
        else:
            value = [200, {'one': 'synthetic-A', 'two': 'synthetic-B'}[rid]]
        result.append(value)
    return result


def audit_receipt(directory, record, payload, binding):
    saved, receipt_hash = read_receipt(directory, record['id'])
    if saved != record or saved.get('binding') != binding:
        raise PolicyError('Candidate receipt binding mismatch')
    if saved.get('payload_sha256') != hashlib.sha256(payload).hexdigest():
        raise PolicyError('Candidate payload hash mismatch')
    if (saved.get('cleanup') != 'PASS' or saved.get('status') != 'COMPLETED'
        or not IMAGE_ID.fullmatch(saved.get('image_id', ''))):
        raise PolicyError('Candidate execution incomplete or cleanup failed: ' + str(saved.get('status')))
    execution, state = saved['execution'], saved['container_state']
    if (type(execution.get('returncode')) is not int or execution['returncode'] != 0
        or type(state.get('ExitCode')) is not int or state['ExitCode'] != 0
        or state.get('Running') is not False or state.get('OOMKilled') is not False or state.get('Error')
        or any(execution.get(k) is not False for k in ('timed_out', 'truncated', 'cancelled'))):
        raise PolicyError('Candidate transport/daemon execution mismatch')
    try:
        observations = json.loads(execution['stdout'])
    except (ValueError, KeyError) as exc:
        raise PolicyError('Candidate observations missing') from exc
    if (not isinstance(observations, list) or len(observations) != len(CASES)
        or any(not isinstance(row, list) or len(row) != 2 or type(row[0]) is not int
               or (row[1] is not None and not isinstance(row[1], str)) for row in observations)):
        raise PolicyError('Invalid candidate observation schema')
    return observations, receipt_hash


def verify_candidate(source, root, *, broker_factory=DockerBroker, limits=Limits()):
    identity = uuid.uuid4().hex
    directory = Path(root) / 'candidate_checks' / identity
    result = dict(id=identity, mode='actual-candidate-docker-fixture', status='BLOCKED',
                  finding_status=None, source_sha256=digest(source), test_sha256=digest(TASK),
                  scope='Actual proposed bytes; restricted fixture language; 15 fixed cases, not a general security proof',
                  proofs=[])
    try:
        validate_candidate(source)
        atomic_text(directory / 'candidate.txt', source)
        broker = broker_factory(Path.cwd())
        receipts = []
        for kind, code, fixed in [('baseline', VULNERABLE, False), ('candidate', source, True), ('recheck', source, True)]:
            payload = job_bytes({'service.py': code, 'task.py': TASK})
            binding = dict(run_id=identity, kind=kind, source_hash=digest(code), test_hash=digest(TASK))
            record = broker.run(payload, directory / 'receipts', limits, binding=binding)
            observed, receipt_hash = audit_receipt(directory / 'receipts', record, payload, binding)
            receipts.append((record, payload, binding, receipt_hash))
            if any(p['receipt_id'] == record['id'] for p in result['proofs']):
                raise PolicyError('Reused candidate receipt')
            if result['proofs'] and result['proofs'][0]['image_id'] != record['image_id']:
                raise PolicyError('Image changed during candidate verification')
            matches = [a == b for a, b in zip(observed, expected(fixed))]
            result['proofs'].append(dict(kind=kind, receipt_id=record['id'], receipt_sha256=receipt_hash,
                                         image_id=record['image_id'], binding=binding, checks=matches,
                                         observed=observed))
            if not all(matches):
                result.update(status='NEEDS_REVIEW', error=kind + ': behavior differs from independent expectations')
                break
        else:
            # Re-read earlier evidence before issuing the final verdict.
            if (directory / 'candidate.txt').read_bytes() != source.encode('utf-8'):
                raise PolicyError('Saved candidate changed during verification')
            for record, payload, binding, receipt_hash in receipts:
                _, current_hash = audit_receipt(directory / 'receipts', record, payload, binding)
                if current_hash != receipt_hash:
                    raise PolicyError('Receipt changed during verification')
            result.update(status='PASS', finding_status='FIXED')
    except KeyboardInterrupt:
        result.update(status='STOPPED', error='Interrupted by operator')
    except (PolicyError, OSError, ValueError, KeyError, TypeError) as exc:
        result['error'] = str(exc)[:2000]
    result['record'] = str(directory / 'summary.json')
    atomic_text(directory / 'summary.json', json.dumps(result, ensure_ascii=False, indent=2))
    return result
