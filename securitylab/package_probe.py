"""S6.3d: bounded multi-module FastAPI HTTP observation from a verified snapshot.

Only explicitly selected service-local UTF-8 .py sources are transferred to the
existing two-container Docker broker. No dependencies, scripts or code from the
repository execute on the host. This is a behavioral probe, not a security scan.
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
from .http_probe import validate_checks
from .http_runner import FastAPIHTTPDockerBroker
from .job_contract import job_bytes
from .policy import Limits, PolicyError
from .repository import _reparse
from .snapshots import _id, _stat_same, verify_snapshot
from .storage import atomic_text

MAX_MODULES = 31  # Plus trusted task.py; contract allows 32 files total.
MAX_MODULE_BYTES = 96 * 1024
MAX_ALL_MODULE_BYTES = 180 * 1024
_MODULE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z', re.ASCII)


def _parts(value: str, *, root: bool = False) -> list[str]:
    if root and value == '.':
        return []
    if (not isinstance(value, str) or not value or len(value) > 512 or
        '\\' in value or ':' in value or value.startswith('/') or
        any(x in ('', '.', '..') for x in value.split('/'))):
        raise PolicyError('Invalid relative service or entry path')
    return value.split('/')


def _member(path: Path, expected: dict) -> str:
    """Read exact verified source bytes via a regular fd with strict hash checks."""
    if expected['size'] > MAX_MODULE_BYTES:
        raise PolicyError('FastAPI package file exceeds 96 KiB')
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or _reparse(before) or path.is_symlink():
            raise PolicyError('Package member is not a regular file')
        flags = (os.O_RDONLY | getattr(os, 'O_BINARY', 0) |
                 getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or not _stat_same(before, opened):
                raise PolicyError('Package member changed on open')
            data = bytearray()
            while len(data) <= MAX_MODULE_BYTES:
                part = os.read(fd, min(65536, MAX_MODULE_BYTES + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            if not _stat_same(opened, os.fstat(fd)):
                raise PolicyError('Package member changed during read')
        finally:
            os.close(fd)
        if not _stat_same(opened, path.lstat()):
            raise PolicyError('Package member changed after read')
    except OSError as exc:
        raise PolicyError('Package member cannot be safely read') from exc
    raw = bytes(data)
    if len(raw) != expected['size'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
        raise PolicyError('Package member hash or size mismatch')
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise PolicyError('Package source must be UTF-8') from exc


def _source_package(store, sid: str, service: str, entry: str):
    """Select only .py entries in one service root; reject unsupported trees."""
    verified = verify_snapshot(store, sid)
    service_parts = _parts(service, root=True)
    entry_parts = _parts(entry)
    service_prefix = '/'.join(service_parts)
    if (service_parts and entry_parts[:len(service_parts)] != service_parts):
        raise PolicyError('FastAPI entry is outside the selected service')
    relative = entry_parts[len(service_parts):]
    if not relative or not relative[-1].endswith('.py'):
        raise PolicyError('FastAPI package entry must be a .py module')
    for segment in relative[:-1] + [relative[-1][:-3]]:
        if not _MODULE.fullmatch(segment):
            raise PolicyError('FastAPI package entry cannot be imported as a module')
    module = '.'.join(relative[:-1] + [relative[-1][:-3]])
    base = store.root / 'snapshots' / sid
    manifest_raw = (base / 'manifest.json').read_bytes()
    if hashlib.sha256(manifest_raw).hexdigest() != verified['manifest_sha256']:
        raise PolicyError('Package manifest changed after verification')
    manifest = json.loads(manifest_raw)
    listed = {row['path']: row for row in manifest['files']}
    entry_key = '/'.join(entry_parts)
    if entry_key not in listed:
        raise PolicyError('FastAPI package entry missing from verified snapshot')
    prefix = service_prefix + '/' if service_prefix else ''
    candidates = sorted(k for k in listed if k.startswith(prefix) and k.endswith('.py'))
    if not 1 <= len(candidates) <= MAX_MODULES:
        raise PolicyError('FastAPI package requires 1..31 .py files in selected service')
    relative_names = [k[len(prefix):] for k in candidates]
    for rel in relative_names:
        segments = rel.split('/')
        if (len(segments) > 5 or
            any(not _MODULE.fullmatch(part) for part in segments[:-1]) or
            not _MODULE.fullmatch(segments[-1][:-3]) or
            segments[-1] == 'task.py' and len(segments) == 1):
            raise PolicyError('Service has unsupported Python module path or reserved task.py')
    if len({n.casefold() for n in relative_names}) != len(relative_names):
        raise PolicyError('Case-insensitive Python package collision')
    relative_set = set(relative_names)
    for rel in relative_names:
        parents = rel.split('/')[:-1]
        for i in range(1, len(parents) + 1):
            if '/'.join(parents[:i]) + '/__init__.py' not in relative_set:
                raise PolicyError('Package directory requires explicit __init__.py')
    if entry_key not in candidates:
        raise PolicyError('Requested entry was not selected')
    total = sum(listed[path]['size'] for path in candidates)
    if total > MAX_ALL_MODULE_BYTES:
        raise PolicyError('FastAPI package source byte limit exceeded')
    source = {}
    identities = []
    for absolute, relative_name in zip(candidates, relative_names):
        content = _member(base / 'workspace' / Path(*absolute.split('/')), listed[absolute])
        source[relative_name] = content
        identities.append({'path': absolute, 'sha256': listed[absolute]['sha256']})
    # A second full verification prevents accidental use of files altered while
    # the bounded source collection was being prepared; not a hostile-host guarantee.
    if verify_snapshot(store, sid)['manifest_sha256'] != verified['manifest_sha256']:
        raise PolicyError('Package snapshot changed during collection')
    digest = hashlib.sha256(json.dumps(identities, separators=(',', ':'),
                                    sort_keys=True).encode()).hexdigest()
    return module, source, digest, listed[entry_key]['sha256'], verified


def package_probe_snapshot(store, snapshot_id: str, entry: str, checks: list[str], *,
                           service: str = '.', execute: bool = False,
                           broker_factory=FastAPIHTTPDockerBroker, limits=Limits()) -> dict:
    if execute is not True:
        raise PolicyError('FastAPI package execution requires explicit --execute')
    parsed = validate_checks(checks)
    sid = _id(snapshot_id)
    module, sources, digest, entry_sha, verified = _source_package(store, sid, service, entry)
    # The only executable entrypoint is written by SecurityLab. The interpolated
    # import name is restricted above to Python identifier components.
    launcher = ("import uvicorn\n"
                f"uvicorn.run({module + ':app'!r}, host='0.0.0.0', port=8000, workers=1, "
                "log_level='warning', access_log=False)\n")
    payload = job_bytes({'task.py': launcher, **sources}, schema_version=2)
    run_id = uuid.uuid4().hex
    folder = store.root / 'package_probes' / run_id
    check_hash = hashlib.sha256(json.dumps(parsed, sort_keys=True,
                       separators=(',', ':')).encode()).hexdigest()
    binding = {'run_id': run_id, 'snapshot_id': sid, 'service': service, 'entry': entry,
               'module': module, 'source_sha256': entry_sha,
               'package_sha256': digest, 'manifest_sha256': verified['manifest_sha256'],
               'checks_sha256': check_hash, 'profile': 'fastapi-package-s63d-v1'}
    report = {'schema_version': 1, 'run_id': run_id, 'mode': 'S6_3D_FASTAPI_PACKAGE_HTTP',
              'snapshot_id': sid, 'entry': entry, 'service': service,
              'module': module, 'source_sha256': entry_sha, 'package_sha256': digest,
              'source_file_count': len(sources),
              'manifest_sha256': verified['manifest_sha256'], 'checks_sha256': check_hash,
              'status': 'BLOCKED', 'security_verdict': 'NOT_EVALUATED',
              'finding_status': None,
              'scope': 'One selected service, up to 31 UTF-8 .py files; baked FastAPI/Uvicorn only',
              'output_trust': 'Independent HTTP observations; application stdout untrusted',
              'checks': parsed}
    try:
        report.update(run_fastapi_http_observation(
            folder, payload, parsed, binding, broker_factory=broker_factory, limits=limits))
    except (PolicyError, OSError, ValueError, TypeError, KeyError) as exc:
        report['error'] = str(exc)[:2000]
    report['record'] = str(folder / 'summary.json')
    atomic_text(folder / 'summary.json', json.dumps(report, ensure_ascii=False, indent=2))
    return report
