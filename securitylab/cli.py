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
    parser = argparse.ArgumentParser(prog='securitylab', description='SecurityLab — scripted demo, no AI; select --executor docker for isolation')
    parser.add_argument('--state', type=Path, default=Path('.securitylab'))
    parser.add_argument('--config', type=Path)
    parser.add_argument('--version', action='version', version=__version__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init')
    sub.add_parser('doctor')
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
    args = parser.parse_args(argv)
    if args.command == 'doctor':
        print(json.dumps({'python': sys.version.split()[0], 'core': 'PASS',
              **{x: 'AVAILABLE_NOT_TESTED' if shutil.which(x) else 'BLOCKED_NOT_INSTALLED'
                 for x in ('git', 'docker', 'hermes', 'ollama', 'nvidia-smi')},
              'note': 'Availability is not an integration test'}, indent=2))
        return 0
    if args.command == 'scan':
        print('BLOCKED: arbitrary repository execution needs a verified isolated runner and live AI integration. No project files changed.', file=sys.stderr)
        return 2
    store = None
    try:
        limits = load_limits(args.config)
        store = Store(args.state)
        engine = Orchestrator(store, limits)
        if args.command == 'init':
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
