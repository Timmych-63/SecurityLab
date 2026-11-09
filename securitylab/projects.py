"""Persistent project registry. Registration never executes or edits source."""
from __future__ import annotations

import json
from pathlib import Path
import time
import uuid

from .policy import PolicyError
from .repository import inventory_repository, repository_root


def assert_state_outside_project(state: Path, source: Path) -> None:
    # Do this BEFORE creating Store (Store creates .securitylab/state.sqlite3).
    state_path = state.resolve()
    source_path = repository_root(source).resolve()
    if state_path == source_path or state_path.is_relative_to(source_path):
        raise PolicyError('State directory must be outside the source repository; use --state <external-directory>')


def _safe_name(value: str) -> str:
    if not 1 <= len(value) <= 80 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise PolicyError('Project name must contain 1..80 printable characters')
    return value


def add_project(store, source: Path, name: str | None = None) -> dict:
    assert_state_outside_project(store.root, source)
    inv = inventory_repository(source)
    label = _safe_name(name if name is not None else source.name)
    project_id = uuid.uuid4().hex
    with store.db:
        store.db.execute('''INSERT INTO projects
          (id, name, source_path, metadata_fingerprint, inventory_json, created)
          VALUES(?,?,?,?,?,?)''',
          (project_id, label, inv['source_path'], inv['metadata_fingerprint'],
           json.dumps(inv, ensure_ascii=False), time.time()))
    return {'id': project_id, 'name': label, 'status': 'REGISTERED_INVENTORY_ONLY', 'inventory': inv}


def list_projects(store) -> list[dict]:
    return [dict(row) for row in store.db.execute('''
        SELECT id,name,source_path,metadata_fingerprint,created
        FROM projects ORDER BY created,id''')]


def project_detail(store, project_id: str) -> dict:
    if not isinstance(project_id, str) or not len(project_id) == 32 or any(c not in '0123456789abcdef' for c in project_id):
        raise PolicyError('Invalid project ID')
    row = store.db.execute('SELECT * FROM projects WHERE id=?', (project_id,)).fetchone()
    if row is None:
        raise PolicyError('Unknown project')
    saved = json.loads(row['inventory_json'])
    try:
        live = inventory_repository(Path(row['source_path']))
        current = 'UNCHANGED_METADATA' if live['metadata_fingerprint'] == row['metadata_fingerprint'] else 'CHANGED_METADATA'
    except (OSError, PolicyError):
        current = 'SOURCE_UNAVAILABLE_OR_UNREADABLE'
    return {'id': project_id, 'name': row['name'], 'source_path': row['source_path'],
            'registration': 'INVENTORY_ONLY', 'source_status': current, 'saved_inventory': saved}
