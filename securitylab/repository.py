"""S6.1 read-only, bounded inventory of untrusted repositories.

Inventory is metadata discovery, not a security scan, source snapshot or permission
for execution. No README, build script or dependency is executed. The host-side
reader assumes the local filesystem owner is trusted; it is not a race-free
filesystem sandbox against a concurrent hostile writer.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import stat
import tomllib

from .policy import PolicyError

MAX_FILES = 10000
MAX_ENTRIES = 20000
MAX_DEPTH = 12
MAX_MANIFEST_BYTES = 128 * 1024
EXCLUDED_DIRS = frozenset({
    '.git', '.hg', '.svn', '.securitylab', '__pycache__', '.venv', 'venv',
    'node_modules', '.next', '.nuxt', '.tox', '.mypy_cache', '.pytest_cache',
    '.ruff_cache', '.idea', '.vscode', 'dist', 'build', 'target', 'coverage',
})
SECRET_NAMES = frozenset({'.env', '.env.local', '.env.production', 'id_rsa', 'id_ed25519'})
SECRET_SUFFIXES = ('.pem', '.p12', '.pfx', '.key')
MARKERS = {
    'pyproject.toml': 'python', 'requirements.txt': 'python',
    'Pipfile': 'python', 'setup.py': 'python',
    'package.json': 'node', 'go.mod': 'go', 'Cargo.toml': 'rust',
    'pom.xml': 'java', 'build.gradle': 'java', 'build.gradle.kts': 'java',
}
EXT_LANG = {
    '.py': 'python', '.js': 'javascript', '.jsx': 'javascript',
    '.ts': 'typescript', '.tsx': 'typescript', '.go': 'go',
    '.rs': 'rust', '.java': 'java', '.cs': 'csharp',
    '.php': 'php', '.rb': 'ruby', '.html': 'html', '.vue': 'vue',
}

# Descriptive profiles only. These are NOT executable profiles or claims of
# verified support for scanning arbitrary code.
PROFILES = (
    {'id': 'python', 'markers': ['pyproject.toml', 'requirements.txt', 'Pipfile', 'setup.py'],
     'inventory': 'AVAILABLE', 'execution': 'NOT_IMPLEMENTED'},
    {'id': 'node', 'markers': ['package.json'],
     'inventory': 'AVAILABLE', 'execution': 'NOT_IMPLEMENTED'},
    {'id': 'go', 'markers': ['go.mod'],
     'inventory': 'AVAILABLE', 'execution': 'NOT_IMPLEMENTED'},
    {'id': 'rust', 'markers': ['Cargo.toml'],
     'inventory': 'AVAILABLE', 'execution': 'NOT_IMPLEMENTED'},
    {'id': 'java', 'markers': ['pom.xml', 'build.gradle', 'build.gradle.kts'],
     'inventory': 'AVAILABLE', 'execution': 'NOT_IMPLEMENTED'},
)


def _reparse(st) -> bool:
    """Reject Windows junction/reparse entries in addition to POSIX symlinks."""
    return bool(getattr(st, 'st_file_attributes', 0) & 0x400)


def repository_root(value: str | Path) -> Path:
    path = Path(value).absolute()
    try:
        st = path.lstat()
    except OSError as exc:
        raise PolicyError('Repository directory cannot be accessed') from exc
    if not stat.S_ISDIR(st.st_mode) or _reparse(st) or path.is_symlink():
        raise PolicyError('Repository root must be a real directory, not a link/junction')
    return path.resolve()


def _read_manifest(path: Path, expected_size: int) -> bytes:
    if expected_size > MAX_MANIFEST_BYTES:
        raise PolicyError('Manifest exceeds size bound')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_MANIFEST_BYTES:
                raise PolicyError('Manifest is not a bounded regular file')
            data = os.read(fd, MAX_MANIFEST_BYTES + 1)
            if len(data) > MAX_MANIFEST_BYTES:
                raise PolicyError('Manifest changed or exceeds size bound')
            return data
        finally:
            os.close(fd)
    except OSError as exc:
        raise PolicyError('Manifest cannot be safely read') from exc


def _details(path: Path, name: str, size: int) -> dict:
    """Extract only declarative names, never script bodies or source content."""
    info = {}
    if name == 'package.json':
        obj = json.loads(_read_manifest(path, size).decode('utf-8-sig'))
        if not isinstance(obj, dict):
            raise ValueError('package.json must be an object')
        scripts = obj.get('scripts', {})
        if isinstance(scripts, dict):
            info['script_names'] = sorted(str(k) for k in scripts if isinstance(k, str))[:40]
        deps = set()
        for key in ('dependencies', 'devDependencies'):
            group = obj.get(key, {})
            if isinstance(group, dict):
                deps.update(k.lower() for k in group if isinstance(k, str))
        info['framework_hints'] = sorted(deps & {'express', 'fastify', 'koa', 'next', 'nestjs', '@nestjs/core'})
    elif name == 'pyproject.toml':
        obj = tomllib.loads(_read_manifest(path, size).decode('utf-8-sig'))
        group = obj.get('project', {})
        deps = group.get('dependencies', []) if isinstance(group, dict) else []
        hints = {'fastapi', 'flask', 'django', 'starlette'}
        if isinstance(deps, list):
            info['framework_hints'] = sorted({dep.split('[', 1)[0].split('=', 1)[0].split('>', 1)[0]
                                              .split('<', 1)[0].strip().lower()
                                              for dep in deps if isinstance(dep, str)} & hints)
    return info


def inventory_repository(value: str | Path) -> dict:
    root = repository_root(value)
    total = 0
    entries_seen = 0
    ignored = 0
    skipped_links = 0
    skipped_special = 0
    secret_count = 0
    tests = 0
    languages: Counter[str] = Counter()
    source_markers: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    manifest_details: dict[str, dict] = {}
    notes: list[str] = []
    digest = hashlib.sha256(b'SecurityLab S6.1 metadata inventory v1\0')
    stack = [(root, 0)]

    while stack:
        directory, depth = stack.pop()
        try:
            children = []
            with os.scandir(directory) as entries:
                for entry in entries:
                    entries_seen += 1
                    if entries_seen > MAX_ENTRIES:
                        raise PolicyError(f'Repository exceeds entry count limit ({MAX_ENTRIES})')
                    children.append(entry)
            children.sort(key=lambda e: e.name)
        except OSError as exc:
            raise PolicyError('Repository contains an inaccessible directory') from exc
        for entry in children:
            # Never recurse through links, junctions or mount-like reparse points.
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise PolicyError('Repository changed during inventory') from exc
            if stat.S_ISLNK(st.st_mode) or _reparse(st):
                skipped_links += 1
                continue
            relative = Path(entry.path).relative_to(root).as_posix()
            if stat.S_ISDIR(st.st_mode):
                if entry.name in EXCLUDED_DIRS:
                    ignored += 1
                    continue
                if depth >= MAX_DEPTH:
                    raise PolicyError(f'Repository exceeds maximum inventory depth ({MAX_DEPTH})')
                stack.append((Path(entry.path), depth + 1))
                continue
            if not stat.S_ISREG(st.st_mode):
                skipped_special += 1
                continue
            total += 1
            if total > MAX_FILES:
                raise PolicyError(f'Repository exceeds file count limit ({MAX_FILES})')
            if entry.name in SECRET_NAMES or entry.name.endswith(SECRET_SUFFIXES) or entry.name.startswith('.env.'):
                secret_count += 1
            # Metadata fingerprint is NOT a content hash and is never used to
            # authenticate the code that will execute in a later stage.
            digest.update(json.dumps([relative, st.st_size, st.st_mtime_ns], ensure_ascii=True,
                                     separators=(',', ':')).encode('utf-8', 'surrogatepass'))
            suffix = Path(entry.name).suffix.lower()
            if suffix in EXT_LANG:
                languages[EXT_LANG[suffix]] += 1
            if (entry.name.startswith('test_') and suffix == '.py') or ('.test.' in entry.name or '.spec.' in entry.name):
                tests += 1
            kind = MARKERS.get(entry.name)
            if kind:
                parent = Path(relative).parent.as_posix()
                source_markers[parent][kind].append(relative)
                if entry.name in {'package.json', 'pyproject.toml'}:
                    try:
                        manifest_details[relative] = _details(Path(entry.path), entry.name, st.st_size)
                    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, PolicyError):
                        notes.append(f'Manifest unreadable/invalid or over limit: {relative}')

    services = []
    for folder, by_language in sorted(source_markers.items()):
        for kind, paths in sorted(by_language.items()):
            hints = set()
            script_names = set()
            for path in paths:
                details = manifest_details.get(path, {})
                hints.update(details.get('framework_hints', []))
                script_names.update(details.get('script_names', []))
            services.append({
                'directory': folder, 'detected_profile': kind,
                'manifest_paths': sorted(paths),
                'framework_hints': sorted(hints), 'script_names': sorted(script_names),
                'execution': 'DISABLED',
            })
    if skipped_links:
        notes.append(f'{skipped_links} symlinks/junctions skipped without following')
    if skipped_special:
        notes.append(f'{skipped_special} nonregular filesystem entries skipped')
    if secret_count:
        notes.append(f'{secret_count} possible secret/key files detected by name; contents not opened')
    notes.append('Metadata fingerprint does not verify source bytes or ensure an atomic filesystem snapshot')
    notes.append('No application code, scripts, dependencies or tests were executed')
    return {
        'schema_version': 1,
        'mode': 'READ_ONLY_INVENTORY',
        'source_path': str(root),
        'metadata_fingerprint': digest.hexdigest(),
        'file_count': total,
        'test_file_count': tests,
        'languages': dict(sorted(languages.items())),
        'services': services,
        'ignored_directory_count': ignored,
        'skipped_link_count': skipped_links,
        'skipped_special_count': skipped_special,
        'possible_secret_file_count': secret_count,
        'notes': notes[:100],
        'scan_permission': 'DENIED',
        'execution_permission': 'DENIED',
    }
