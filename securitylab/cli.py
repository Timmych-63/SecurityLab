import argparse
import json
from pathlib import Path
import shutil
import sys
from . import __version__
from .config import load_limits
from .orchestrator import Orchestrator
from .policy import PolicyError, Limits
from .report import report
from .storage import Store, worker_lock

def main(argv=None):
    parser = argparse.ArgumentParser(prog='securitylab', description='SecurityLab — isolated fixture checks and constrained Hermes proposals')
    parser.add_argument('--state', type=Path, default=Path('.securitylab'))
    parser.add_argument('--config', type=Path)
    parser.add_argument('--version', action='version', version=__version__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init')
    sub.add_parser('doctor')
    sub.add_parser('ai-smoke')
    ai = sub.add_parser('ai-demo')
    ai.add_argument('--verify-candidate', action='store_true', help='S5: execute actual bounded fixture proposal')
    candidate = sub.add_parser('candidate-check')
    candidate.add_argument('--summary', type=Path, required=True, help='Saved AI summary containing blue proposal')
    demo = sub.add_parser('demo')
    demo.add_argument('--enqueue', action='store_true')
    demo.add_argument('--executor', choices=['local', 'docker'], default='local')
    worker = sub.add_parser('worker')
    worker.add_argument('--run')
    for cmd in ('stop', 'retry', 'rollback', 'findings', 'history'):
        p = sub.add_parser(cmd)
        p.add_argument('run')
    status = sub.add_parser('status')
    status.add_argument('run', nargs='?')
    rep = sub.add_parser('report')
    rep.add_argument('run')
    rep.add_argument('--output', type=Path)
    scan = sub.add_parser('scan')
    scan.add_argument('project', type=Path)
    sub.add_parser('profiles', help='List detection profiles (no execution profiles yet)')
    repo = sub.add_parser('repo', help='S6 repository discovery and inert snapshots; no project execution')
    repo_sub = repo.add_subparsers(dest='repo_command', required=True)
    for action in ('inspect', 'add'):
        p = repo_sub.add_parser(action)
        p.add_argument('path', type=Path)
        if action == 'add':
            p.add_argument('--name')
    repo_sub.add_parser('list')
    show = repo_sub.add_parser('show')
    show.add_argument('project_id')
    for action in ('snapshot', 'snapshots'):
        p = repo_sub.add_parser(action)
        p.add_argument('project_id')
    for action in ('verify-snapshot', 'plan'):
        p = repo_sub.add_parser(action)
        p.add_argument('snapshot_id')
    probe = repo_sub.add_parser('probe', help='Explicit standalone Python Docker probe (NOT a security scan)')
    probe.add_argument('snapshot_id')
    probe.add_argument('--entry', required=True, help='Exact .py path inside the verified snapshot')
    probe.add_argument('--execute', action='store_true', help='Explicitly permit untrusted code execution in Docker')
    http_probe = repo_sub.add_parser('http-probe', help='S6.3b opt-in independent HTTP observation in two containers')
    http_probe.add_argument('snapshot_id')
    http_probe.add_argument('--entry', required=True, help='Single-file stdlib HTTP server, binding 0.0.0.0:8000')
    http_probe.add_argument('--expect', action='append', default=[], help='Independent contract PATH=STATUS (repeat 1..8 times)')
    http_probe.add_argument('--execute', action='store_true')
    fastapi_probe = repo_sub.add_parser('fastapi-probe', help='S6.3c explicit single-module FastAPI observation')
    fastapi_probe.add_argument('snapshot_id')
    fastapi_probe.add_argument('--entry', required=True, help='Exact .py path exporting FastAPI app')
    fastapi_probe.add_argument('--expect', action='append', default=[], help='PATH=STATUS (1..8 checks)')
    fastapi_probe.add_argument('--execute', action='store_true')
    package_probe = repo_sub.add_parser('fastapi-package-probe', help='S6.3d opt-in bounded multi-module FastAPI observation')
    package_probe.add_argument('snapshot_id')
    package_probe.add_argument('--service', default='.', help='Service subdirectory (default: snapshot root)')
    package_probe.add_argument('--entry', required=True, help='Exact .py path within snapshot; app must be exported')
    package_probe.add_argument('--expect', action='append', default=[], help='PATH=STATUS (1..8 checks)')
    package_probe.add_argument('--execute', action='store_true')
    access = repo_sub.add_parser('access-baseline',
        help='S7.1 operator-authored access policy observed by independent Docker HTTP verifier')
    access.add_argument('snapshot_id')
    access.add_argument('--service', default='.', help='Selected service directory in verified snapshot')
    access.add_argument('--entry', required=True, help='FastAPI package module exporting app')
    access.add_argument('--policy', type=Path, required=True,
                        help='External trusted JSON policy outside tested project/state')
    access.add_argument('--execute', action='store_true')
    access_ai = repo_sub.add_parser('access-ai',
        help='S7.2 opt-in Red/Blue bounded FastAPI access fix and independent Git/HTTP recheck')
    access_ai.add_argument('snapshot_id')
    access_ai.add_argument('--service', default='.')
    access_ai.add_argument('--entry', required=True)
    access_ai.add_argument('--policy', type=Path, required=True)
    access_ai.add_argument('--execute', action='store_true')
    args = parser.parse_args(argv)
    if args.command == 'doctor':
        print(json.dumps({'python': sys.version.split()[0], 'core': 'PASS',
              **{x: 'AVAILABLE_NOT_TESTED' if shutil.which(x) else 'BLOCKED_NOT_INSTALLED'
                 for x in ('git', 'docker', 'hermes', 'ollama', 'nvidia-smi')},
              'note': 'Host executable availability only; container Hermes/model integration is tested by ai-smoke'}, indent=2))
        return 0
    if args.command == 'scan':
        print('BLOCKED: arbitrary repository execution needs a verified isolated runner and live AI integration. No project files changed.', file=sys.stderr)
        return 2
    if args.command == 'profiles':
        from .repository import PROFILES
        print(json.dumps({'profiles': PROFILES, 'scan': 'DISABLED', 'execution': 'DISABLED'},
                         ensure_ascii=False, indent=2))
        return 0
    if args.command == 'repo' and args.repo_command == 'inspect':
        from .repository import inventory_repository
        try:
            print(json.dumps(inventory_repository(args.path), ensure_ascii=False, indent=2))
            return 0
        except (PolicyError, OSError) as exc:
            print(f'ERROR: {exc}', file=sys.stderr)
            return 2
    if args.command == 'repo' and args.repo_command == 'add':
        from .projects import assert_state_outside_project
        try:
            assert_state_outside_project(args.state, args.path)
        except (PolicyError, OSError) as exc:
            print(f'ERROR: {exc}', file=sys.stderr)
            return 2
    store = None
    try:
        limits = load_limits(args.config)
        store = Store(args.state)
        engine = Orchestrator(store, limits)
        if args.command in {'ai-smoke', 'ai-demo'}:
            from .ai_workflow import run_ai
            result = run_ai(store, smoke=args.command == 'ai-smoke', candidate=getattr(args, 'verify_candidate', False))
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result['status'] == 'PASS' else 2
        if args.command == 'candidate-check':
            from .ai_contract import strict_json, validate_proposal
            from .candidate_verifier import verify_candidate
            with args.summary.open('rb') as handle:
                raw = handle.read(32769)
            saved = strict_json(raw.decode('utf-8'))
            blue = validate_proposal('blue', saved.get('blue'), candidate=True)
            (store.root / 'ai').mkdir(parents=True, exist_ok=True)
            with worker_lock(store.root / 'ai'):
                result = verify_candidate(blue['content'], store.root, limits=limits)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result['status'] == 'PASS' else 2
        if args.command == 'repo':
            from .projects import add_project, list_projects, project_detail
            if args.repo_command == 'add':
                result = add_project(store, args.path, args.name)
            elif args.repo_command == 'list':
                result = list_projects(store)
            elif args.repo_command == 'show':
                result = project_detail(store, args.project_id)
            elif args.repo_command == 'probe':
                from .probe_runner import probe_snapshot
                result = probe_snapshot(store, args.snapshot_id, args.entry, execute=args.execute, limits=limits)
            elif args.repo_command == 'http-probe':
                from .http_probe import http_probe_snapshot
                result = http_probe_snapshot(store, args.snapshot_id, args.entry, args.expect, execute=args.execute, limits=limits)
            elif args.repo_command == 'fastapi-probe':
                from .fastapi_probe import fastapi_probe_snapshot
                result = fastapi_probe_snapshot(store, args.snapshot_id, args.entry, args.expect, execute=args.execute, limits=limits)
            elif args.repo_command == 'fastapi-package-probe':
                from .package_probe import package_probe_snapshot
                result = package_probe_snapshot(store, args.snapshot_id, args.entry, args.expect, service=args.service,
                                                execute=args.execute, limits=limits)
            elif args.repo_command == 'access-baseline':
                from .access_baseline import access_baseline_snapshot
                result = access_baseline_snapshot(store, args.snapshot_id, args.entry, args.policy,
                                                  service=args.service, execute=args.execute, limits=limits)
            elif args.repo_command == 'access-ai':
                from .access_ai import run_access_ai
                result = run_access_ai(store, args.snapshot_id, args.entry, args.policy,
                                       service=args.service, execute=args.execute, limits=limits)
            elif args.repo_command in {'snapshot', 'snapshots', 'verify-snapshot', 'plan'}:
                from .snapshots import create_snapshot, list_snapshots, verify_snapshot
                if args.repo_command == 'snapshot':
                    result = create_snapshot(store, args.project_id)
                elif args.repo_command == 'snapshots':
                    result = list_snapshots(store, args.project_id)
                elif args.repo_command == 'verify-snapshot':
                    result = verify_snapshot(store, args.snapshot_id)
                else:
                    from .profile_plan import plan_snapshot
                    result = plan_snapshot(store, args.snapshot_id)
            else:
                raise PolicyError('Unknown repository command')
        elif args.command == 'init':
            result = {'state': str(store.root), 'schema_version': 1}
        elif args.command == 'demo':
            rid = store.create("scripted-demo-docker-no-ai" if args.executor == "docker" else "scripted-demo-no-ai")
            result = store.get(rid) if args.enqueue else engine.run(rid)
            if not args.enqueue:
                report_path = report(store, rid, store.root / 'runs' / rid / 'report')
                result['finding_status'] = (store.finding(rid) or {}).get('status')
                result['report'] = str(report_path)
        elif args.command == 'worker':
            ids = [args.run] if args.run else [r['id'] for r in store.runs() if r['status'] in {'QUEUED', 'RUNNING'}]
            result = [engine.run(rid) for rid in ids]
        elif args.command == 'status':
            result = store.get(args.run) if args.run else store.runs()
        elif args.command == 'stop':
            store.stop(args.run)
            result = store.get(args.run)
        elif args.command == 'retry':
            with worker_lock(store.root):
                store.retry(args.run, limits.max_attempts)
            result = store.get(args.run)
        elif args.command == 'rollback':
            result = engine.rollback(args.run)
        elif args.command == 'findings':
            result = store.finding(args.run)
        elif args.command == 'history':
            result = store.history(args.run)
        elif args.command == 'report':
            output = args.output or store.root / 'runs' / args.run / 'report'
            # Validate ID before creating any output directory.
            store.get(args.run)
            result = {'report': str(report(store, args.run, output))}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.command == 'repo' and args.repo_command == 'access-ai':
            return 0 if result['status'] == 'PASS' else 2
        if args.command == 'repo' and args.repo_command == 'access-baseline':
            return {'ACCESS_POLICY_MATCHED': 0, 'ACCESS_POLICY_VIOLATION_REPRODUCED': 3}.get(result['status'], 2)
        if args.command == 'repo' and args.repo_command in {'http-probe', 'fastapi-probe', 'fastapi-package-probe'}:
            return 0 if result['status'] == 'HTTP_CHECKS_PASSED' else 2
        if args.command == 'repo' and args.repo_command == 'probe':
            return 0 if result['status'] in {'EXECUTED_UNTRUSTED', 'NONZERO_EXIT_UNTRUSTED'} else 2
        if args.command in {'demo', 'worker'}:
            rows = result if isinstance(result, list) else [result]
            if any(r['status'] in {'BLOCKED', 'STOPPED'} for r in rows):
                return 2
            if any((store.finding(r['id']) or {}).get('status') == 'NEEDS_REVIEW' for r in rows):
                return 2
        return 0
    except (PolicyError, OSError, ValueError) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 2
    finally:
        if store:
            store.close()
