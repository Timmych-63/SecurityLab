"""S6.3c limited FastAPI/ASGI HTTP observation; no arbitrary dependencies.

A single verified UTF-8 Python module must expose `app`. The developer-owned
launcher imports it in the baked, explicitly selected FastAPI image. The
independent verifier remains the original minimal image.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import uuid

from .container_runner import IMAGE_ID
from .http_probe import validate_checks
from .http_runner import FastAPIHTTPDockerBroker
from .job_contract import job_bytes
from .policy import Limits, PolicyError
from .probe_runner import _load_verified_entry
from .snapshots import _id
from .storage import atomic_text

# Fixed code, not sourced from a repository, README, manifest, or AI response.
ASGI_LAUNCHER = '''import uvicorn
uvicorn.run('project:app', host='0.0.0.0', port=8000, workers=1,
            log_level='warning', access_log=False)
'''


def fastapi_probe_snapshot(store, snapshot_id: str, entry: str, checks: list[str], *,
                           execute: bool = False, broker_factory=FastAPIHTTPDockerBroker,
                           limits=Limits()) -> dict:
    if execute is not True:
        raise PolicyError('FastAPI execution requires explicit --execute')
    parsed = validate_checks(checks)
    sid = _id(snapshot_id)
    raw, source_hash, verified = _load_verified_entry(store, sid, entry)
    try:
        source = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise PolicyError('FastAPI entry must be UTF-8') from exc
    payload = job_bytes({'task.py': ASGI_LAUNCHER, 'project.py': source})
    run_id = uuid.uuid4().hex
    folder = store.root / 'fastapi_probes' / run_id
    check_hash = hashlib.sha256(json.dumps(parsed, sort_keys=True,
                      separators=(',', ':')).encode()).hexdigest()
    binding = {'run_id': run_id, 'snapshot_id': sid, 'entry': entry,
               'source_sha256': source_hash,
               'manifest_sha256': verified['manifest_sha256'],
               'checks_sha256': check_hash, 'profile': 'fastapi-s63c-v1'}
    report = {'schema_version': 1, 'run_id': run_id, 'mode': 'S6_3C_FASTAPI_HTTP',
              'snapshot_id': sid, 'entry': entry, 'source_sha256': source_hash,
              'manifest_sha256': verified['manifest_sha256'], 'checks_sha256': check_hash,
              'status': 'BLOCKED', 'security_verdict': 'NOT_EVALUATED',
              'finding_status': None,
              'scope': 'One Python module exposing app; image-baked FastAPI and Uvicorn only',
              'output_trust': 'External HTTP observations; application stdout untrusted',
              'checks': parsed}
    try:
        broker = broker_factory(Path.cwd())
        result = broker.run(payload, parsed, folder, binding=binding, limits=limits)
        receipt = folder / 'docker_receipt.json'
        raw_receipt = receipt.read_bytes()
        if len(raw_receipt) > 1048576:
            raise PolicyError('Oversized FastAPI broker receipt')
        saved = json.loads(raw_receipt.decode('utf-8'))
        if (saved != result or saved.get('binding') != binding or
            saved.get('source_payload_sha256') != hashlib.sha256(payload).hexdigest() or
            saved.get('checks_sha256') != check_hash or saved.get('cleanup') != 'PASS' or
            not IMAGE_ID.fullmatch(saved.get('image_id', '')) or
            not IMAGE_ID.fullmatch(saved.get('target_image_id', ''))):
            raise PolicyError('Invalid FastAPI broker receipt or cleanup')
        if saved['status'] not in {'HTTP_CHECKS_PASSED', 'HTTP_CHECKS_FAILED'}:
            raise PolicyError(saved.get('error', 'FastAPI runtime did not complete'))
        observed = saved.get('observations')
        if not isinstance(observed, list) or len(observed) != len(parsed):
            raise PolicyError('Missing independent FastAPI HTTP observations')
        for expected, actual in zip(parsed, observed):
            if (not isinstance(actual, dict) or actual.get('path') != expected['path'] or
                actual.get('expected_status') != expected['expected_status'] or
                type(actual.get('actual_status')) is not int or
                type(actual.get('passed')) is not bool or
                actual['passed'] != (actual['actual_status'] == expected['expected_status'])):
                raise PolicyError('Contradictory FastAPI HTTP observation')
        if (saved['status'] == 'HTTP_CHECKS_PASSED') != all(x['passed'] for x in observed):
            raise PolicyError('FastAPI HTTP verifier status contradictory')
        report.update(status=saved['status'], observations=observed,
                      image_id=saved['image_id'], target_image_id=saved['target_image_id'],
                      cleanup='PASS', receipt_sha256=hashlib.sha256(raw_receipt).hexdigest())
    except (PolicyError, OSError, ValueError, TypeError, KeyError) as exc:
        report['error'] = str(exc)[:2000]
    report['record'] = str(folder / 'summary.json')
    atomic_text(folder / 'summary.json', json.dumps(report, ensure_ascii=False, indent=2))
    return report
