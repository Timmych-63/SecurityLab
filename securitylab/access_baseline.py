"""S7.1: independent, operator-authored access-control baseline observations.

This is NOT a free-form scanner, AI verdict, or Blue patch verifier. It runs one
bounded FastAPI package via the S6.3d broker and an independent HTTP observer.
The trusted contract lives outside the examined repository and snapshot.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from .fastapi_probe import run_fastapi_http_observation
from .http_runner import FastAPIHTTPDockerBroker
from .job_contract import job_bytes
from .package_probe import _source_package
from .policy import Limits, PolicyError
from .snapshots import _id, _stat_same
from .storage import atomic_text

MAX_POLICY_BYTES = 12 * 1024
_ID = re.compile(r'[a-z][a-z0-9_-]{0,47}\Z', re.ASCII)
_ACTOR = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,31}\Z', re.ASCII)
_PATH = re.compile(r'/[A-Za-z0-9._~/?&=+!$(),;:@-]{0,240}\Z', re.ASCII)
_SHA = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise PolicyError('Duplicate field in policy JSON')
        obj[key] = value
    return obj


def read_external_policy(store, snapshot_id: str, path: Path) -> tuple[dict, str]:
    """Read an explicit, independent file, not a policy embedded by the target."""
    if not isinstance(path, Path):
        raise PolicyError('Explicit policy file path required')
    try:
        path = path.absolute()
        source_row = store.db.execute('''SELECT p.source_path FROM projects p
            JOIN project_snapshots s ON s.project_id=p.id WHERE s.id=?''',
            (snapshot_id,)).fetchone()
        if source_row is None:
            raise PolicyError('Unknown policy snapshot')
        source_root = Path(source_row['source_path']).resolve()
        state_root = store.root.resolve()
        # No policy file from within the untrusted repository or local state.
        if path.resolve().is_relative_to(source_root) or path.resolve().is_relative_to(state_root):
            raise PolicyError('Policy must be outside project and SecurityLab state')
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink() or not 0 < before.st_size <= MAX_POLICY_BYTES:
            raise PolicyError('Policy must be a bounded regular file without symlinks')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or not _stat_same(before, opened):
                raise PolicyError('Policy file changed on open')
            raw = bytearray()
            while len(raw) <= MAX_POLICY_BYTES:
                chunk = os.read(fd, min(4096, MAX_POLICY_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if not _stat_same(opened, os.fstat(fd)):
                raise PolicyError('Policy file changed during read')
        finally:
            os.close(fd)
        if not _stat_same(opened, path.lstat()) or len(raw) != opened.st_size:
            raise PolicyError('Policy file changed after read')
    except OSError as exc:
        raise PolicyError('Policy file cannot be safely read') from exc
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError('Policy byte limit exceeded')
    try:
        policy = json.loads(bytes(raw).decode('utf-8'), object_pairs_hook=_unique_pairs)
    except PolicyError:
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        raise PolicyError('Policy must be strict UTF-8 JSON') from exc
    validate_policy(policy)
    return policy, hashlib.sha256(raw).hexdigest()


def validate_policy(policy: dict) -> None:
    if (not isinstance(policy, dict) or set(policy) != {'schema_version', 'policy_id', 'checks'} or
        type(policy['schema_version']) is not int or policy['schema_version'] != 1 or
        not isinstance(policy['policy_id'], str) or not _ID.fullmatch(policy['policy_id']) or
        not isinstance(policy['checks'], list) or not 2 <= len(policy['checks']) <= 8):
        raise PolicyError('Unsupported independent access policy schema')
    ids = {}
    pairs = set()
    has_control = has_deny = False
    for index, check in enumerate(policy['checks']):
        if not isinstance(check, dict) or check.get('kind') not in ('control', 'deny'):
            raise PolicyError('Policy check kind must be control or deny')
        kind = check['kind']
        wanted = {'id', 'kind', 'path', 'actor', 'expected_status'}
        if kind == 'deny':
            wanted.add('compare_body_to')
        else:
            wanted.add('expected_body_sha256')
        if set(check) != wanted:
            raise PolicyError('Policy check fields incorrect')
        ident, actor, path, expected = (check['id'], check['actor'], check['path'],
                                       check['expected_status'])
        if (not isinstance(ident, str) or not _ID.fullmatch(ident) or ident in ids or
            not isinstance(actor, str) or not _ACTOR.fullmatch(actor) or
            not isinstance(path, str) or not _PATH.fullmatch(path) or
            path.startswith('//') or '/..' in path or
            (actor, path) in pairs or type(expected) is not int):
            raise PolicyError('Unsafe, duplicate or invalid access policy check')
        if kind == 'control':
            if expected != 200:
                raise PolicyError('Control check must expect HTTP 200')
            if not isinstance(check['expected_body_sha256'],str) or not _SHA.fullmatch(check['expected_body_sha256']):
                raise PolicyError('Control requires operator-anchored expected body SHA-256')
            has_control = True
        else:
            if expected not in (401, 403):
                raise PolicyError('Denied check must expect HTTP 401 or 403')
            referenced = check['compare_body_to']
            other = ids.get(referenced) if isinstance(referenced, str) else None
            if (other is None or other['kind'] != 'control' or
                other['path'] != path or other['actor'] == actor):
                raise PolicyError('Denied check must refer to earlier control with same path and different actor')
            has_deny = True
        pairs.add((actor, path))
        ids[ident] = check
    if not (has_control and has_deny):
        raise PolicyError('Policy needs at least one control and one denied check')


def _classify(policy: dict, observations: list[dict]) -> tuple[str, str, str | None, list[dict]]:
    if len(observations) != len(policy['checks']):
        raise PolicyError('Incomplete independent access observations')
    by_id = {}
    explanations = []
    for check, actual in zip(policy['checks'], observations):
        expected_shape = {'path', 'expected_status', 'actual_status', 'passed', 'error',
                          'actor', 'body_sha256', 'body_bytes', 'body_truncated'}
        if (not isinstance(actual, dict) or set(actual) != expected_shape or
            actual['path'] != check['path'] or actual['actor'] != check['actor'] or
            actual['expected_status'] != check['expected_status'] or
            type(actual['actual_status']) is not int or not 100 <= actual['actual_status'] <= 599 or
            actual['error'] is not None or type(actual['passed']) is not bool or
            actual['passed'] != (actual['actual_status'] == check['expected_status']) or
            not isinstance(actual['body_sha256'], str) or not _SHA.fullmatch(actual['body_sha256']) or
            type(actual['body_bytes']) is not int or not 0 <= actual['body_bytes'] <= 4097 or
            type(actual['body_truncated']) is not bool or
            actual['body_truncated'] != (actual['body_bytes'] > 4096)):
            raise PolicyError('Independent access evidence contradicted contract')
        if actual['body_truncated']:
            raise PolicyError('Independent access response exceeded 4096-byte body evidence limit')
        by_id[check['id']] = actual
    controls = [(c, by_id[c['id']]) for c in policy['checks'] if c['kind'] == 'control']
    if not all(a['passed'] and a['body_bytes'] > 0 and
               a['body_sha256'] == c['expected_body_sha256'] for c, a in controls):
        return 'NEEDS_REVIEW', 'NOT_EVALUATED', None, [{'reason':'Control did not return the operator-anchored expected body SHA-256'}]
    reproduced = []
    unresolved = []
    for check in policy['checks']:
        if check['kind'] != 'deny':
            continue
        actual = by_id[check['id']]
        source = by_id[check['compare_body_to']]
        if actual['passed']:
            explanations.append({'id':check['id'], 'result':'DENIED_AS_REQUIRED'})
        elif (actual['actual_status'] == 200 and actual['body_bytes'] > 0 and
              actual['body_sha256'] == source['body_sha256'] and
              actual['body_bytes'] == source['body_bytes']):
            reproduced.append(check['id'])
            explanations.append({'id':check['id'], 'result':'UNAUTHORIZED_BODY_MATCHES_CONTROL'})
        else:
            unresolved.append(check['id'])
            explanations.append({'id':check['id'], 'result':'UNEXPECTED_RESPONSE_NEEDS_REVIEW'})
    if reproduced:
        return ('ACCESS_POLICY_VIOLATION_REPRODUCED', 'POLICY_VIOLATION_OBSERVED',
                'REPRODUCED', explanations)
    if unresolved:
        return 'NEEDS_REVIEW', 'NOT_EVALUATED', None, explanations
    return 'ACCESS_POLICY_MATCHED', 'NOT_PROVEN_SAFE', None, explanations


def access_baseline_snapshot(store, snapshot_id: str, entry: str, policy_path: Path, *,
                             service: str = '.', execute: bool = False,
                             broker_factory=FastAPIHTTPDockerBroker,
                             limits=Limits()) -> dict:
    if execute is not True:
        raise PolicyError('Access baseline requires explicit --execute')
    sid = _id(snapshot_id)
    policy, policy_hash = read_external_policy(store, sid, policy_path)
    module, sources, package_hash, source_hash, verified = _source_package(store, sid, service, entry)
    launcher = ('import uvicorn\n' +
                f"uvicorn.run({module + ':app'!r}, host='0.0.0.0', port=8000, workers=1, " +
                "log_level='warning', access_log=False)\n")
    payload = job_bytes({'task.py':launcher, **sources}, schema_version=2)
    checks = [{'path':c['path'], 'expected_status':c['expected_status'], 'actor':c['actor']}
              for c in policy['checks']]
    checks_hash = hashlib.sha256(json.dumps(checks,sort_keys=True,
                                 separators=(',',':')).encode()).hexdigest()
    run_id = uuid.uuid4().hex
    folder = store.root / 'access_baselines' / run_id
    binding = {'run_id':run_id, 'snapshot_id':sid, 'service':service, 'entry':entry,
               'source_sha256':source_hash, 'package_sha256':package_hash,
               'manifest_sha256':verified['manifest_sha256'], 'checks_sha256':checks_hash,
               'policy_sha256':policy_hash, 'profile':'access-baseline-s71-v1'}
    report = {'schema_version':1, 'run_id':run_id, 'mode':'S7_1_ACCESS_BASELINE',
              'snapshot_id':sid, 'service':service, 'entry':entry,
              'manifest_sha256':verified['manifest_sha256'], 'package_sha256':package_hash,
              'policy_id':policy['policy_id'], 'policy_sha256':policy_hash,
              'checks_sha256':checks_hash, 'status':'BLOCKED',
              'security_verdict':'NOT_EVALUATED', 'finding_status':None,
              'scope':'Explicit trusted access policy with expected control body hashes; synthetic X-Test-User header; bounded FastAPI package',
              'note':'This is an operator-defined baseline, not an autonomous Red/Blue security scan'}
    try:
        observed = run_fastapi_http_observation(folder, payload, checks, binding,
                    broker_factory=broker_factory, limits=limits)
        # The helper already re-reads the actual trusted-broker receipt and
        # rejects tampering, partial execution, image mismatch, and cleanup failure.
        status, verdict, finding, details = _classify(policy, observed['observations'])
        report.update(observed)
        report.update(status=status, security_verdict=verdict, finding_status=finding,
                      observations=observed['observations'], outcomes=details)
    except (PolicyError, OSError, ValueError, TypeError, KeyError) as exc:
        report['error'] = str(exc)[:2000]
    report['record'] = str(folder / 'summary.json')
    atomic_text(folder / 'summary.json', json.dumps(report, ensure_ascii=False, indent=2))
    return report
