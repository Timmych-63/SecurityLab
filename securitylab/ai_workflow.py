"""Sequential Red/Blue proposals followed by the reviewed S3 verification exercise."""
import json
from pathlib import Path
import uuid
from .ai_contract import request, validate_proposal, digest, reviewed_variant
from .hermes_adapter import HermesAdapter
from .orchestrator import Orchestrator
from .policy import PolicyError
from .report import report
from .storage import atomic_text, worker_lock


def run_ai(store, smoke=False, adapter_factory=HermesAdapter, engine_factory=Orchestrator):
    aid = uuid.uuid4().hex
    directory = store.root / 'ai' / aid
    directory.mkdir(parents=True, exist_ok=True)
    summary = {'id': aid, 'mode': 'hermes-smoke' if smoke else 'hermes-constrained-fixture',
               'status': 'BLOCKED', 'verification_run': None, 'finding_status': None,
               'scope': 'Known synthetic fixture only; AI proposals are not evidence'}
    try:
        # One model task at a time. Separate lock avoids nesting the S3 queue lock.
        with worker_lock(store.root / 'ai'):
            adapter = adapter_factory(Path.cwd(), directory / 'calls')
            if smoke:
                _, call = adapter.ask(request('smoke'))
                summary.update(status='PASS', calls=[call['id']], model=call['response']['model'],
                               model_digest=call['response']['model_digest'])
            else:
                red, red_call = adapter.ask(request('red'))
                validate_proposal('red', red)
                summary['red'] = red
                atomic_text(directory / 'summary.json', json.dumps(summary, ensure_ascii=False, indent=2))
                blue, blue_call = adapter.ask(request('blue', red))
                validate_proposal('blue', blue)
                if red_call['response']['model_digest'] != blue_call['response']['model_digest']:
                    raise PolicyError('Model changed between Red and Blue')
                summary.update(blue=blue, blue_attempts=blue_call.get('attempt', 1), calls=[red_call['id'], blue_call['id']],
                               proposal_sha256=digest(blue),
                               reviewed_variant=reviewed_variant(blue['content']),
                               canonicalization='Reviewed fixture variant mapped to canonical FIXED; original proposal not executed')
                # Only after the AI gate passed: execute the equivalent reviewed fixture,
                # retaining the S3 no-AI mode truthfully for this child verification run.
                rid = store.create('scripted-demo-docker-no-ai')
                summary['verification_run'] = rid
                atomic_text(directory / 'summary.json', json.dumps(summary, ensure_ascii=False, indent=2))
                outcome = engine_factory(store).run(rid)
                finding = store.finding(rid) or {}
                summary['finding_status'] = finding.get('status')
                summary['verification_status'] = outcome['status']
                summary['report'] = str(report(store, rid, store.root / 'runs' / rid / 'report'))
                summary['status'] = 'PASS' if outcome['status'] == 'DONE' and finding.get('status') == 'FIXED' else 'BLOCKED'
    except KeyboardInterrupt:
        summary.update(status='STOPPED', error='Interrupted by operator')
    except (PolicyError, OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        summary['error'] = str(exc)[:2000]
    finally:
        summary['record'] = str(directory / 'summary.json')
        atomic_text(directory / 'summary.json', json.dumps(summary, ensure_ascii=False, indent=2))
    return summary
