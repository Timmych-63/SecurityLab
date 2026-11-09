"""S6.2: bounded local copy of *untrusted* repository bytes.

No source files are imported, parsed as Python, or executed. A snapshot is
not a security sandbox, immutable storage, or a race-free view of a tree that
is being changed by an adversary. Only the trusted host process writes here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
import uuid

from .policy import PolicyError
from .repository import (MAX_DEPTH, MAX_ENTRIES, MAX_FILES, EXCLUDED_DIRS,
                         _reparse, inventory_repository, repository_root)
from .projects import assert_state_outside_project

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
CHUNK = 64 * 1024
# Known high-risk filename patterns, intentionally not a complete secret detector.
SECRET_NAMES = frozenset({
    '.env', '.env.local', '.env.production', '.env.development', '.env.test',
    '.npmrc', '.pypirc', '.netrc', 'id_rsa', 'id_ed25519', 'credentials',
    'credentials.json', 'service-account.json', 'service_account.json',
    'secrets.json', 'secrets.yaml', 'secrets.yml',
})
SECRET_ENDINGS = ('.pem', '.p12', '.pfx', '.key', '.jks', '.keystore', '.kdbx')


def _secret(filename: str) -> bool:
    lower = filename.lower()
    return (lower in SECRET_NAMES or lower.startswith('.env.') or
            lower.endswith(SECRET_ENDINGS) or lower.startswith('id_rsa_') or
            lower.startswith('id_ed25519_'))


def _valid_part(name: str) -> bool:
    # Conservative across Windows and POSIX. Paths originate from scandir, not
    # LLM output; still reject ambiguous names and Windows device names.
    if not name or name in {'.', '..'} or name.endswith((' ', '.')) or any(
            ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF or c in '\\/:*?"<>|' for c in name):
        return False
    stem = name.split('.')[0].upper()
    return stem not in ({'CON', 'PRN', 'AUX', 'NUL'} |
                        {f'COM{i}' for i in range(1, 10)} |
                        {f'LPT{i}' for i in range(1, 10)})


def _safe_dir(path: Path) -> None:
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or _reparse(st) or path.is_symlink():
        raise PolicyError('Snapshot directory must be a real directory')


def _stat_same(before, after) -> bool:
    """Compare freshly queried path/handle metadata, not cached DirEntry data."""
    return (before.st_size, before.st_mtime_ns, before.st_dev, before.st_ino) == (
        after.st_size, after.st_mtime_ns, after.st_dev, after.st_ino)


def _entry_matches_fresh(cached, fresh) -> bool:
    """Compare a directory listing with a fresh lstat across Windows/POSIX.

    On Windows os.DirEntry.stat(follow_symlinks=False) sets st_dev and st_ino
    to ZERO even for regular files (Python 3.13 documentation); pathlib.lstat
    and os.fstat can return real identifiers. Never use a zero from the cached
    listing as the identity of the opened file. Fresh lstat <-> fstat remains
    a strict identity comparison in _stat_same.
    """
    if (stat.S_IFMT(cached.st_mode), cached.st_size, cached.st_mtime_ns) != (
            stat.S_IFMT(fresh.st_mode), fresh.st_size, fresh.st_mtime_ns):
        return False
    return (not cached.st_dev or not fresh.st_dev or cached.st_dev == fresh.st_dev) and (
        not cached.st_ino or not fresh.st_ino or cached.st_ino == fresh.st_ino)


def _fresh_regular(path: Path, listing, label: str):
    """Reject a replaced/reparse path, then pin subsequent comparisons to lstat."""
    try:
        fresh = path.lstat()
    except OSError as exc:
        raise PolicyError(f'{label} cannot be safely checked') from exc
    if (not stat.S_ISREG(fresh.st_mode) or _reparse(fresh) or path.is_symlink()
            or not _entry_matches_fresh(listing, fresh)):
        raise PolicyError(f'{label} changed between enumeration and open')
    return fresh


def _copy_regular(source: Path, target: Path, observed, remaining: int) -> tuple[str, int]:
    if observed.st_size > MAX_FILE_BYTES:
        raise PolicyError('Snapshot source file exceeds per-file bound')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    # The lstat plus fstat checks are best effort on Windows, which lacks the
    # Linux openat2 RESOLVE_BENEATH primitive. Do not operate on hostile live trees.
    try:
        src_fd = os.open(source, flags)
        try:
            fst = os.fstat(src_fd)
            if not stat.S_ISREG(fst.st_mode) or not _stat_same(observed, fst):
                raise PolicyError('Source changed between enumeration and open')
            digest = hashlib.sha256()
            copied = 0
            with target.open('xb') as dest:
                while True:
                    part = os.read(src_fd, min(CHUNK, MAX_FILE_BYTES - copied + 1))
                    if not part:
                        break
                    copied += len(part)
                    if copied > MAX_FILE_BYTES or copied > remaining:
                        raise PolicyError('Snapshot byte limit exceeded')
                    digest.update(part)
                    dest.write(part)
                dest.flush()
                os.fsync(dest.fileno())
            if not _stat_same(fst, os.fstat(src_fd)) or copied != fst.st_size:
                raise PolicyError('Source changed during copy')
            after = source.lstat()
            if not stat.S_ISREG(after.st_mode) or _reparse(after) or not _stat_same(fst, after):
                raise PolicyError('Source changed after copy')
            return digest.hexdigest(), copied
        finally:
            os.close(src_fd)
    except OSError as exc:
        raise PolicyError('Source file cannot be safely copied') from exc


def _walk_and_copy(source: Path, work: Path) -> tuple[list[dict], int, int, int]:
    files: list[dict] = []
    bytes_used = entry_count = ignored_secrets = 0
    # Case-insensitive collision protection for snapshots that may be transported
    # between Linux and Windows later.
    names_seen: set[str] = set()
    stack: list[tuple[Path, Path, int]] = [(source, Path('.'), 0)]
    while stack:
        directory, relative_dir, depth = stack.pop()
        _safe_dir(directory)
        if directory.stat().st_dev != source.stat().st_dev:
            raise PolicyError('Snapshot refuses cross-device directory traversal')
        children = []
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > MAX_ENTRIES:
                        raise PolicyError('Snapshot entry count limit exceeded')
                    children.append(entry)
        except OSError as exc:
            raise PolicyError('Snapshot source directory cannot be listed') from exc
        for entry in sorted(children, key=lambda e: e.name):
            if not _valid_part(entry.name):
                raise PolicyError('Snapshot source contains unsafe filename')
            rel = relative_dir / entry.name
            key = rel.as_posix().casefold()
            if key in names_seen:
                raise PolicyError('Case-insensitive path collision')
            names_seen.add(key)
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise PolicyError('Snapshot source changed during walk') from exc
            if stat.S_ISLNK(st.st_mode) or _reparse(st):
                # Omit links, never follow. This can yield an incomplete copy.
                continue
            if stat.S_ISDIR(st.st_mode):
                if entry.name in EXCLUDED_DIRS:
                    continue
                if depth >= MAX_DEPTH:
                    raise PolicyError('Snapshot depth limit exceeded')
                stack.append((Path(entry.path), rel, depth + 1))
            elif stat.S_ISREG(st.st_mode):
                if _secret(entry.name):
                    ignored_secrets += 1
                    continue
                if len(files) >= MAX_FILES:
                    raise PolicyError('Snapshot file count limit exceeded')
                if st.st_size > MAX_FILE_BYTES or bytes_used + st.st_size > MAX_SNAPSHOT_BYTES:
                    raise PolicyError('Snapshot file or total byte limit exceeded')
                destination = work / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                source_path = Path(entry.path)
                # Windows DirEntry.stat() has zero st_dev/st_ino, unlike fstat.
                # A fresh lstat both checks for replacement and provides an
                # identity that can actually be compared with the open handle.
                fresh = _fresh_regular(source_path, st, 'Source')
                digest, size = _copy_regular(source_path, destination, fresh, MAX_SNAPSHOT_BYTES - bytes_used)
                bytes_used += size
                files.append({'path': rel.as_posix(), 'size': size, 'sha256': digest})
            else:
                # FIFO/device/socket ignored; never open, even to check data.
                continue
    return sorted(files, key=lambda x: x['path']), bytes_used, ignored_secrets, entry_count


def _id(value: str) -> str:
    if not isinstance(value, str) or len(value) != 32 or any(ch not in '0123456789abcdef' for ch in value):
        raise PolicyError('Invalid snapshot ID')
    return value


def _registered(store, project_id: str):
    _id(project_id)
    row = store.db.execute('SELECT * FROM projects WHERE id=?', (project_id,)).fetchone()
    if row is None:
        raise PolicyError('Unknown project')
    return row


def _snapshots_parent(store) -> Path:
    parent = store.root / 'snapshots'
    parent.mkdir(exist_ok=True)
    _safe_dir(parent)
    return parent


def create_snapshot(store, project_id: str) -> dict:
    row = _registered(store, project_id)
    root = repository_root(row['source_path'])
    assert_state_outside_project(store.root, root)
    if root.is_relative_to(store.root):
        raise PolicyError('A project cannot be nested inside SecurityLab state')
    before = inventory_repository(root)
    parent = _snapshots_parent(store)
    sid = uuid.uuid4().hex
    target = parent / sid
    stage = Path(tempfile.mkdtemp(prefix='.stage-', dir=parent))
    published = False
    try:
        workspace = stage / 'workspace'
        workspace.mkdir()
        files, total_bytes, skipped, entries = _walk_and_copy(root, workspace)
        after = inventory_repository(root)
        if before['metadata_fingerprint'] != after['metadata_fingerprint']:
            raise PolicyError('Repository metadata changed while snapshotting; retry on a stable copy')
        manifest = {
            'schema_version': 1, 'mode': 'LOCAL_CONTENT_HASHED_COPY',
            'project_id': project_id, 'snapshot_id': sid,
            'source_path': str(root), 'metadata_fingerprint': before['metadata_fingerprint'],
            'files': files, 'file_count': len(files), 'total_bytes': total_bytes,
            'skipped_possible_secret_files': skipped,
            'entries_checked': entries,
            'execution_permission': 'DENIED',
            'notes': [
                'Snapshot is a local content-hashed copy, not a race-free filesystem snapshot',
                'Filename-based secret detection is incomplete; review before sharing',
                'No source commands or dependency scripts executed',
                'Excluded files/links mean this may not be a complete runnable project',
            ],
        }
        manifest_bytes = (json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')) + '\n').encode('utf-8')
        (stage / 'manifest.json').write_bytes(manifest_bytes)
        if len(manifest_bytes) > 2 * 1024 * 1024:
            raise PolicyError('Snapshot manifest size limit exceeded')
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        if target.exists():
            raise PolicyError('Snapshot ID collision')
        stage.rename(target)
        published = True
        with store.db:
            store.db.execute('''INSERT INTO project_snapshots
                (id,project_id,created,manifest_sha256,file_count,total_bytes,skipped_secrets)
                VALUES (?,?,?,?,?,?,?)''',
                (sid, project_id, time.time(), manifest_hash, len(files), total_bytes, skipped))
        return {'snapshot_id': sid, 'project_id': project_id, 'mode': manifest['mode'],
                'workspace': str(target / 'workspace'), 'manifest': str(target / 'manifest.json'),
                'manifest_sha256': manifest_hash, 'file_count': len(files),
                'total_bytes': total_bytes, 'skipped_possible_secret_files': skipped,
                'status': 'CREATED_UNVERIFIED', 'execution_permission': 'DENIED'}
    except BaseException:
        if published:
            shutil.rmtree(target, ignore_errors=True)
        raise
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def list_snapshots(store, project_id: str) -> list[dict]:
    _registered(store, project_id)
    return [dict(row) for row in store.db.execute('''
        SELECT id,project_id,created,file_count,total_bytes,skipped_secrets
        FROM project_snapshots WHERE project_id=? ORDER BY created,id''', (project_id,))]


def verify_snapshot(store, snapshot_id: str) -> dict:
    sid = _id(snapshot_id)
    row = store.db.execute('SELECT * FROM project_snapshots WHERE id=?', (sid,)).fetchone()
    if row is None:
        raise PolicyError('Unknown snapshot')
    parent = _snapshots_parent(store)
    base = parent / sid
    _safe_dir(base)
    workspace = base / 'workspace'
    _safe_dir(workspace)
    manifest_path = base / 'manifest.json'
    mst = manifest_path.lstat()
    if not stat.S_ISREG(mst.st_mode) or _reparse(mst) or manifest_path.is_symlink() or mst.st_size > 2 * 1024 * 1024:
        raise PolicyError('Snapshot manifest is invalid or unbounded')
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != row['manifest_sha256']:
        raise PolicyError('Snapshot manifest checksum mismatch')
    manifest = json.loads(raw)
    if (manifest.get('snapshot_id') != sid or manifest.get('project_id') != row['project_id'] or
        manifest.get('mode') != 'LOCAL_CONTENT_HASHED_COPY' or
        manifest.get('file_count') != row['file_count'] or
        manifest.get('total_bytes') != row['total_bytes']):
        raise PolicyError('Snapshot manifest does not match registry')
    expected = manifest.get('files')
    if not isinstance(expected, list) or len(expected) != row['file_count'] or len(expected) > MAX_FILES:
        raise PolicyError('Snapshot file manifest is invalid')
    mapping = {}
    expected_dirs = set()
    casefolded = set()
    for item in expected:
        if not isinstance(item, dict) or set(item) != {'path', 'sha256', 'size'}:
            raise PolicyError('Snapshot manifest entry is invalid')
        rel = item['path']
        if (not isinstance(rel, str) or not rel or '\\' in rel or
                any(not _valid_part(x) for x in rel.split('/')) or
                not isinstance(item['size'], int) or item['size'] < 0 or item['size'] > MAX_FILE_BYTES or
                not isinstance(item['sha256'], str) or len(item['sha256']) != 64 or
                any(c not in '0123456789abcdef' for c in item['sha256']) or rel in mapping):
            raise PolicyError('Snapshot manifest contains an invalid path, size or hash')
        folded = rel.casefold()
        if folded in casefolded:
            raise PolicyError('Snapshot manifest has a case-insensitive collision')
        casefolded.add(folded)
        mapping[rel] = item
        parts = rel.split('/')
        for i in range(1, len(parts)):
            expected_dirs.add('/'.join(parts[:i]))
    seen = set()
    stack = [(workspace, Path('.'), 0)]
    visited_entries = 0
    total = 0
    while stack:
        dirpath, relpath, depth = stack.pop()
        _safe_dir(dirpath)
        with os.scandir(dirpath) as it:
            entries = list(it)
        for entry in entries:
            visited_entries += 1
            if visited_entries > MAX_ENTRIES or not _valid_part(entry.name):
                raise PolicyError('Snapshot verification entry count or name invalid')
            rel = (relpath / entry.name).as_posix()
            st = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode) or _reparse(st):
                raise PolicyError('Unexpected link in snapshot')
            if stat.S_ISDIR(st.st_mode):
                if rel not in expected_dirs:
                    raise PolicyError('Snapshot contains an extra directory')
                if depth >= MAX_DEPTH:
                    raise PolicyError('Snapshot verification depth limit exceeded')
                stack.append((Path(entry.path), relpath / entry.name, depth + 1))
            elif stat.S_ISREG(st.st_mode):
                if rel not in mapping or rel in seen:
                    raise PolicyError('Snapshot contains an extra or duplicate file')
                fresh = _fresh_regular(Path(entry.path), st, 'Snapshot file')
                if fresh.st_size != mapping[rel]['size']:
                    raise PolicyError('Snapshot file size mismatch')
                flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
                fd = os.open(entry.path, flags)
                try:
                    fst = os.fstat(fd)
                    if not stat.S_ISREG(fst.st_mode) or not _stat_same(fresh, fst):
                        raise PolicyError('Snapshot file changed during verification')
                    digest = hashlib.sha256()
                    received = 0
                    while True:
                        data = os.read(fd, CHUNK)
                        if not data:
                            break
                        received += len(data)
                        if received > st.st_size:
                            raise PolicyError('Snapshot file grew during verification')
                        digest.update(data)
                    if not _stat_same(fst, os.fstat(fd)) or received != st.st_size:
                        raise PolicyError('Snapshot changed while verifying')
                finally:
                    os.close(fd)
                if digest.hexdigest() != mapping[rel]['sha256']:
                    raise PolicyError('Snapshot file checksum mismatch')
                total += received
                seen.add(rel)
            else:
                raise PolicyError('Unexpected special filesystem entry in snapshot')
    if seen != set(mapping) or total != row['total_bytes']:
        raise PolicyError('Snapshot has missing files or invalid byte total')
    return {'snapshot_id': sid, 'project_id': row['project_id'],
            'status': 'VERIFIED_CONTENT_HASHES', 'file_count': len(seen),
            'total_bytes': total, 'manifest_sha256': row['manifest_sha256'],
            'execution_permission': 'DENIED'}
