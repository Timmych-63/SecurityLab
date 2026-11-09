"""S6.3a: explicitly opted-in, single-file Python execution in existing DockerBroker.

This is NOT an API/service runner, a vulnerability scan, or a trusted test oracle.
Source is never executed on the host; Docker stdout is never a security verdict.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

from .container_runner import DockerBroker, IMAGE_ID
from .docker_fixture import read_receipt
from .job_contract import job_bytes
from .policy import Limits, PolicyError
from .snapshots import _id, _reparse, _stat_same, verify_snapshot
from .storage import atomic_text

MAX_SOURCE_BYTES = 96 * 1024


def _load_verified_entry(store, snapshot_id: str, entry: str) -> tuple[bytes, str, dict]:
    """Use exact manifest membership, recheck bytes from an opened regular handle."""
    check = verify_snapshot(store, snapshot_id)
    if (not isinstance(entry, str) or not entry or len(entry) > 512 or not entry.endswith('.py')
        or '\\' in entry or ':' in entry or entry.startswith('/') or
        any(part in {'', '.', '..'} for part in entry.split('/'))):
        raise PolicyError('Probe entry must be a relative manifest-listed Python file')
    base = store.root / 'snapshots' / snapshot_id
    manifest_raw = (base / 'manifest.json').read_bytes()
    if hashlib.sha256(manifest_raw).hexdigest() != check['manifest_sha256']:
        raise PolicyError('Snapshot manifest changed after verification')
    manifest = json.loads(manifest_raw)
    items = [item for item in manifest['files'] if item['path'] == entry]
    if len(items) != 1:
        raise PolicyError('Probe entry is not in the verified snapshot')
    expected = items[0]
    if expected['size'] > MAX_SOURCE_BYTES:
        raise PolicyError('Python probe source exceeds 96 KiB')
    path = base / 'workspace' / Path(*entry.split('/'))
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or _reparse(before) or path.is_symlink():
        raise PolicyError('Probe entry changed type')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or not _stat_same(before, opened):
                raise PolicyError('Probe entry changed on open')
            raw = bytearray()
            while len(raw) <= MAX_SOURCE_BYTES:
                chunk = os.read(fd, min(65536, MAX_SOURCE_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > MAX_SOURCE_BYTES or not _stat_same(opened, os.fstat(fd)):
                raise PolicyError('Probe entry changed during read')
        finally:
            os.close(fd)
    except OSError as exc:
        raise PolicyError('Cannot safely open probe entry') from exc
    if not _stat_same(opened, path.lstat()):
        raise PolicyError('Probe entry changed after read')
    data = bytes(raw)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != expected['size'] or digest != expected['sha256']:
        raise PolicyError('Probe entry content checksum mismatch')
    return data, digest, check


def _audit(record: dict, receipt_dir: Path, payload: bytes, binding: dict) -> tuple[dict, str]:
    saved, receipt_hash = read_receipt(receipt_dir, record['id'])
    if (saved != record or saved.get('binding') != binding or
        saved.get('payload_sha256') != hashlib.sha256(payload).hexdigest() or
        not IMAGE_ID.fullmatch(saved.get('image_id', ''))):
        raise PolicyError('Probe Docker receipt or binding invalid')
    if saved.get('cleanup') != 'PASS':
        raise PolicyError('Probe Docker cleanup was not confirmed')
    if saved.get('status') not in {'COMPLETED', 'NONZERO_EXIT'}:
        raise PolicyError('Probe incomplete: ' + str(saved.get('status')))
    state = saved.get('container_state', {})
    r = saved.get('execution', {})
    if (state.get('Running') is not False or state.get('OOMKilled') is not False or state.get('Error') or
        type(state.get('ExitCode')) is not int or type(r.get('returncode')) is not int or
        r['returncode'] != state['ExitCode'] or
        any(r.get(flag) is not False for flag in ('truncated', 'cancelled', 'timed_out')) or
        (saved['status'] == 'COMPLETED') != (state['ExitCode'] == 0)):
        raise PolicyError('Probe runtime observations inconsistent or incomplete')
    return saved, receipt_hash


def probe_snapshot(store, snapshot_id: str, entry: str, *, execute: bool = False,
                   broker_factory=DockerBroker, limits=Limits()) -> dict:
    """Never runs unless explicit opt-in; always returns NOT_A_SECURITY_VERDICT."""
    sid = _id(snapshot_id)
    if execute is not True:
        raise PolicyError('Code execution requires explicit --execute')
    raw, source_hash, verified = _load_verified_entry(store, sid, entry)
    try:
        content = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise PolicyError('Probe source must be UTF-8') from exc
    payload = job_bytes({'task.py': content})
    identity = uuid.uuid4().hex
    directory = store.root / 'probes' / identity
    binding = {'probe_id': identity, 'snapshot_id': sid, 'entry': entry,
               'source_sha256': source_hash, 'manifest_sha256': verified['manifest_sha256']}
    summary = {'schema_version': 1, 'probe_id': identity, 'mode': 'S6_3_STANDALONE_PYTHON_DOCKER',
               'snapshot_id': sid, 'entry': entry, 'source_sha256': source_hash,
               'manifest_sha256': verified['manifest_sha256'], 'status': 'BLOCKED',
               'finding_status': None, 'security_verdict': 'NOT_EVALUATED',
               'scope': 'Single UTF-8 Python file, no dependencies, no imports from repository, no network',
               'output_trust': 'UNTRUSTED; stdout, exit code and stderr cannot establish security'}
    try:
        broker = broker_factory(Path.cwd())
        record = broker.run(payload, directory / 'receipts', limits, binding=binding)
        saved, digest = _audit(record, directory / 'receipts', payload, binding)
        summary.update(status='EXECUTED_UNTRUSTED' if saved['status'] == 'COMPLETED' else
                       'NONZERO_EXIT_UNTRUSTED', receipt_id=saved['id'], receipt_sha256=digest,
                       image_id=saved['image_id'], exit_code=saved['container_state']['ExitCode'],
                       cleanup='PASS')
    except (PolicyError, OSError, ValueError, KeyError, TypeError) as exc:
        summary['error'] = str(exc)[:2000]
    summary['record'] = str(directory / 'summary.json')
    atomic_text(directory / 'summary.json', json.dumps(summary, ensure_ascii=False, indent=2))
    return summary
