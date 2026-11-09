"""S6.3b: opt-in, two-container Python stdlib HTTP observation.

HTTP observations come from a separate trusted verifier container, never from
application stdout. Passing a caller-supplied contract IS NOT a security verdict.
No dependencies, ports published to host, host mounts, or production secrets.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import uuid

from .http_runner import HTTPDockerBroker
from .container_runner import IMAGE_ID
from .job_contract import job_bytes
from .policy import Limits, PolicyError
from .probe_runner import _load_verified_entry
from .snapshots import _id
from .storage import atomic_text

MAX_CHECKS = 8
_PATH = re.compile(r'/[A-Za-z0-9._~/?&=+!$(),;:@-]{0,240}\Z', re.ASCII)


def validate_checks(expressions: list[str]) -> list[dict]:
    if not isinstance(expressions, list) or not 1 <= len(expressions) <= MAX_CHECKS:
        raise PolicyError('HTTP profile requires 1..8 explicit --expect PATH=STATUS checks')
    result = []
    seen = set()
    for item in expressions:
        if not isinstance(item, str) or '=' not in item:
            raise PolicyError('Expected HTTP check PATH=STATUS')
        path, status = item.rsplit('=', 1)
        if (not _PATH.fullmatch(path) or path.startswith('//') or '/..' in path or
            '#' in path or any(ord(c) < 33 or ord(c) > 126 for c in path)):
            raise PolicyError('HTTP check path must be a bounded, local ASCII path')
        if not status.isascii() or not re.fullmatch(r'[2-5][0-9]{2}', status):
            raise PolicyError('Expected HTTP status must be 200..599')
        code = int(status)
        if code > 599 or path in seen:
            raise PolicyError('Repeated path or invalid HTTP status')
        seen.add(path)
        result.append({'path': path, 'expected_status': code})
    return result


def http_probe_snapshot(store, snapshot_id: str, entry: str, checks: list[str], *,
                        execute: bool = False, broker_factory=HTTPDockerBroker,
                        limits=Limits()) -> dict:
    if execute is not True:
        raise PolicyError('HTTP project execution requires explicit --execute')
    parsed_checks = validate_checks(checks)
    sid = _id(snapshot_id)
    raw, source_hash, verified = _load_verified_entry(store, sid, entry)
    try:
        source = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise PolicyError('HTTP entry must be UTF-8') from exc
    payload = job_bytes({'task.py': source})
    run_id = uuid.uuid4().hex
    folder = store.root / 'http_probes' / run_id
    checks_hash = hashlib.sha256(json.dumps(parsed_checks, sort_keys=True,
                             separators=(',', ':')).encode('utf-8')).hexdigest()
    binding = {'run_id': run_id, 'snapshot_id': sid, 'entry': entry,
               'source_sha256': source_hash, 'manifest_sha256': verified['manifest_sha256'],
               'checks_sha256': checks_hash}
    report = {'schema_version': 1, 'run_id': run_id, 'mode': 'S6_3B_PYTHON_STDLIB_HTTP',
              'snapshot_id': sid, 'entry': entry, 'source_sha256': source_hash,
              'manifest_sha256': verified['manifest_sha256'], 'checks_sha256': checks_hash,
              'status': 'BLOCKED', 'security_verdict': 'NOT_EVALUATED',
              'finding_status': None, 'scope': 'Single-file Python stdlib HTTP service on internal Docker network',
              'output_trust': 'HTTP responses are independent observations; application stdout is untrusted',
              'checks': parsed_checks}
    try:
        broker = broker_factory(Path.cwd())
        result = broker.run(payload, parsed_checks, folder, binding=binding, limits=limits)
        # Broker controls its own receipts. Re-read instead of trusting a return value.
        receipt_path = folder / 'docker_receipt.json'
        receipt_raw = receipt_path.read_bytes()
        if len(receipt_raw) > 1048576:
            raise PolicyError('Oversized HTTP broker receipt')
        saved = json.loads(receipt_raw.decode('utf-8'))
        if (saved != result or saved.get('binding') != binding or
            saved.get('source_payload_sha256') != hashlib.sha256(payload).hexdigest() or
            saved.get('checks_sha256') != checks_hash or saved.get('cleanup') != 'PASS' or
            not IMAGE_ID.fullmatch(saved.get('image_id', '')) or
            not IMAGE_ID.fullmatch(saved.get('target_image_id', ''))):
            raise PolicyError('Invalid HTTP broker receipt or incomplete cleanup')
        if saved['status'] not in {'HTTP_CHECKS_PASSED', 'HTTP_CHECKS_FAILED'}:
            raise PolicyError(saved.get('error', 'HTTP execution did not complete'))
        observed = saved.get('observations')
        if not isinstance(observed, list) or len(observed) != len(parsed_checks):
            raise PolicyError('Incomplete independent HTTP observations')
        for expected, actual in zip(parsed_checks, observed):
            if (not isinstance(actual, dict) or actual.get('path') != expected['path'] or
                actual.get('expected_status') != expected['expected_status'] or
                type(actual.get('actual_status')) is not int or
                type(actual.get('passed')) is not bool or
                actual['passed'] != (actual['actual_status'] == expected['expected_status'])):
                raise PolicyError('Inconsistent HTTP verifier observations')
        if (saved['status'] == 'HTTP_CHECKS_PASSED') != all(row['passed'] for row in observed):
            raise PolicyError('HTTP status contradicts independent observations')
        report.update(status=saved['status'], observations=observed,
                      image_id=saved['image_id'], target_image_id=saved['target_image_id'],
                      cleanup='PASS',
                      receipt_sha256=hashlib.sha256(receipt_raw).hexdigest())
    except (PolicyError, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        report['error'] = str(exc)[:2000]
    report['record'] = str(folder / 'summary.json')
    atomic_text(folder / 'summary.json', json.dumps(report, ensure_ascii=False, indent=2))
    return report
