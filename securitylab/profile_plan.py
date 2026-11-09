"""S6.2 descriptive readiness plan: no build/start/test command execution."""
from __future__ import annotations

from .policy import PolicyError
from .snapshots import verify_snapshot

PROFILE_CAPABILITIES = {
    'python': {'kind': 'python-service', 'stage': 'PLANNED_NO_RUNNER'},
    'node': {'kind': 'node-service', 'stage': 'PLANNED_NO_RUNNER'},
    'go': {'kind': 'go-service', 'stage': 'DETECTION_ONLY'},
    'rust': {'kind': 'rust-service', 'stage': 'DETECTION_ONLY'},
    'java': {'kind': 'java-service', 'stage': 'DETECTION_ONLY'},
}


def plan_snapshot(store, sid: str) -> dict:
    check = verify_snapshot(store, sid)
    base = store.root / 'snapshots' / sid / 'manifest.json'
    import json
    manifest = json.loads(base.read_text(encoding='utf-8'))
    # Inventory again from the verified workspace: do not trust saved manifest
    # service claims if the source has changed since registration.
    from .repository import inventory_repository
    inv = inventory_repository(store.root / 'snapshots' / sid / 'workspace')
    services = []
    for service in inv['services']:
        profile = service['detected_profile']
        capability = PROFILE_CAPABILITIES.get(profile)
        if capability is None:
            raise PolicyError('Unrecognized profile in inventory')
        services.append({
            'directory': service['directory'], 'detected_profile': profile,
            'profile_stage': capability['stage'],
            'planned_adapter': capability['kind'],
            'build': 'DISABLED', 'start': 'DISABLED', 'test': 'DISABLED',
            'missing_gates': ['PINNED_RUNTIME', 'TRUSTED_DEPENDENCY_PREP',
                              'ISOLATED_RUNNER', 'EXTERNAL_EVIDENCE_CHECKER'],
        })
    return {
        'schema_version': 1, 'mode': 'NON_EXECUTING_PROFILE_PLAN',
        'snapshot_id': sid, 'snapshot_status': check['status'],
        'services': services, 'multi_service': len(services) > 1,
        'source_files': manifest['file_count'],
        'scan_permission': 'DENIED', 'execution_permission': 'DENIED',
        'note': 'A profile plan is NOT permission to execute README, npm scripts or arbitrary commands',
    }
