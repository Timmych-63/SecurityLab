"""S11 research cycle: Red decides, core executes tools and verifies.

Budgets, boundaries and tools are enforced here, not by the model. Findings
become findings only after independent reproduction on a fresh stand. Nothing
writes to the source repository; patches stay in an isolated Git copy.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import re
import time
import uuid
from pathlib import Path

from . import app_map, research_contract as contract
from .access_ai import _audit_ai_receipt, _git, _jsonsha, _observe, _prepare_git, _sha
from .access_baseline import validate_policy
from .ai_config import AIConfig
from .fastapi_probe import run_fastapi_http_observation
from .hermes_adapter import HermesAdapter, ProposalRejected
from .http_runner import FastAPIHTTPDockerBroker
from .job_contract import job_bytes
from .package_probe import _source_package
from .policy import Limits, PolicyError, safe_path
from .research_prepare import MAX_DOCUMENT_BYTES, validate_setup
from .snapshots import _id, verify_snapshot
from .storage import atomic_text, worker_lock

PREP_ID = re.compile(r'[a-f0-9]{32}\Z', re.ASCII)
_SUMMARY_LIMIT = 256 * 1024


def _read_bounded(path: Path, limit: int) -> bytes:
    raw = path.read_bytes()
    if len(raw) > limit:
        raise PolicyError('Saved file exceeds audit bound: ' + path.name)
    return raw


def load_preparation(store, preparation_id: str):
    """Re-read the saved preparation and re-verify its hashes; never trust memory."""
    if not isinstance(preparation_id, str) or not PREP_ID.fullmatch(preparation_id):
        raise PolicyError('Invalid preparation ID')
    folder = store.root / 'research_preparations' / preparation_id
    summary_path = folder / 'summary.json'
    if not summary_path.is_file():
        raise PolicyError('Unknown research preparation: ' + preparation_id)
    summary = json.loads(_read_bounded(summary_path, _SUMMARY_LIMIT).decode('utf-8'))
    if summary.get('status') == 'SUPERSEDED':
        raise PolicyError('Подготовка отменена более новой подготовкой: ' +
                          str(summary.get('superseded_by', '?')))
    if summary.get('status') != 'PREPARED' or summary.get('execution_ready') is not False:
        raise PolicyError('Preparation is not usable for execution')
    knowledge_hash = hashlib.sha256(
        _read_bounded(folder / 'knowledge.md', MAX_DOCUMENT_BYTES)).hexdigest()
    setup_hash = hashlib.sha256(
        _read_bounded(folder / 'setup.json', MAX_DOCUMENT_BYTES)).hexdigest()
    if summary.get('knowledge_sha256') != knowledge_hash or summary.get('setup_sha256') != setup_hash:
        raise PolicyError('Подготовка изменилась после сохранения; повторите prepare-research')
    actors = summary.get('actors')
    if not isinstance(actors, dict) or not actors:
        raise PolicyError('Подготовка создана старой версией без списка аккаунтов; '
                          'повторите prepare-research')
    return summary, folder


def research_readiness(store, preparation_id: str) -> dict:
    """Static readiness: preparation inputs and project compatibility. No Docker/model."""
    result = {'preparationId': preparation_id, 'prepare': 'untested', 'project': 'untested',
              'ready': False, 'details': {}}
    try:
        summary, _ = load_preparation(store, preparation_id)
        result['prepare'] = 'verified'
        result['details']['prepare'] = 'Подготовка и входные данные проверены; статус PREPARED.'
    except (PolicyError, OSError, ValueError) as exc:
        result['prepare'] = 'error'
        result['details']['prepare'] = str(exc)[:1500]
        return result
    try:
        sources, _, verified, mapping = load_project(store, summary)
        result['project'] = 'verified'
        result['details']['project'] = (
            'Поддерживаемый профиль: %d Python-модулей, %d GET-маршрутов; '
            'зависимости образа FastAPI.' % (len(sources),
                                             sum(1 for r in mapping['routes'] if r['method'] == 'GET')))
        result['ready'] = True
    except (PolicyError, OSError, ValueError) as exc:
        result['project'] = 'error'
        result['details']['project'] = ('Проект не проходит проверку совместимости: '
                                        + str(exc)[:1200])
    return result


def load_project(store, summary):
    """Verified snapshot sources plus static compatibility map (no model, no Docker)."""
    sid = _id(summary['snapshot_id'])
    module, sources, package_hash, entry_hash, verified = _source_package(
        store, sid, summary['service'], summary['entry'])
    relative = _relative(summary['entry'], summary['service'])
    mapping = app_map.inventory(sources, relative)
    return sources, module, verified, mapping


def _relative(entry: str, service: str) -> str:
    prefix = [] if service == '.' else service.split('/')
    return '/'.join(entry.split('/')[len(prefix):])


def _compact_map(mapping: dict) -> dict:
    return {'entry': mapping['entry'],
            'files': [row['file'] for row in mapping['files']],
            'routes': [{'method': r['method'], 'path': r['path'], 'file': r['file']}
                       for r in mapping['routes']],
            'dependencies': list(mapping['dependencies'])}


def _launcher(module: str) -> str:
    return ('import uvicorn\n'
            f"uvicorn.run({module + ':app'!r}, host='0.0.0.0', port=8000, workers=1, "
            "log_level='warning', access_log=False)\n")


class _Budget:
    def __init__(self, budget: dict):
        self.total = dict(budget)
        self.started = time.monotonic()
        self.decisions = 0
        self.requests = 0
        self.verifier_requests = 0

    @property
    def seconds_used(self) -> int:
        return int(time.monotonic() - self.started)

    def note(self) -> dict:
        return {'decisions_left': max(0, self.total['decisions'] - self.decisions),
                'requests_left': max(0, self.total['requests'] - self.requests),
                'seconds_left': max(0, self.total['seconds'] - self.seconds_used)}

    def coverage(self) -> dict:
        return {'decisions_used': self.decisions, 'requests_used': self.requests,
                'verification_requests': self.verifier_requests,
                'seconds_used': self.seconds_used, 'budget': dict(self.total)}


def run_research_cycle(store, preparation_id: str, *, execute=False,
                       adapter_factory=HermesAdapter,
                       broker_factory=FastAPIHTTPDockerBroker,
                       observer=run_fastapi_http_observation, limits=Limits(),
                       run_id=None, stop=None, progress=None):
    if execute is not True:
        raise PolicyError('Research cycle requires explicit execute')
    identity = _id(run_id) if run_id is not None else uuid.uuid4().hex
    folder = store.root / 'research' / identity
    emit = progress or (lambda *args: None)

    def checkpoint():
        if stop is not None and stop():
            raise PolicyError('Cancelled by operator')

    def cleanup_confirmed() -> bool:
        paths = list((folder / 'calls').glob('*.json')) + list(folder.glob('*/docker_receipt.json'))
        try:
            return all(json.loads(p.read_text('utf-8')).get('cleanup') == 'PASS' for p in paths)
        except (OSError, ValueError):
            return False

    result = {'schema_version': 1, 'run_id': identity, 'mode': contract.MODE,
              'profileId': contract.PROFILE, 'preparation_id': preparation_id,
              'status': 'BLOCKED', 'finding_status': None,
              'security_verdict': 'NOT_EVALUATED',
              'scope': 'Self-directed research of one bounded FastAPI package on the prepared '
                       'local stand; independent verification; no auto-merge',
              'output_trust': 'AI hypotheses are proposals; violations require independent '
                              'reproduction',
              'stages': {}, 'ai_calls': [], 'candidates': [], 'hypotheses': [],
              'notes': [], 'record': str(folder / 'summary.json')}
    budget = None
    try:
        summary, prep_folder = load_preparation(store, preparation_id)
        sid = _id(summary['snapshot_id'])
        service, entry = summary['service'], summary['entry']
        config = validate_setup(json.loads(
            _read_bounded(prep_folder / 'setup.json', MAX_DOCUMENT_BYTES).decode('utf-8')))
        actors = config['actors']
        budget = _Budget(summary['budget'])
        sources, module, verified, mapping = load_project(store, summary)
        relative = _relative(entry, service)
        knowledge_text = _read_bounded(prep_folder / 'knowledge.md',
                                       MAX_DOCUMENT_BYTES).decode('utf-8')
        result.update(snapshot_id=sid, entry=entry, service=service, module=module,
                      manifest_sha256=verified['manifest_sha256'])
        payload = job_bytes({'task.py': _launcher(module), **sources}, schema_version=2)
        observed_raw: list[dict] = []
        ai_audits: list[tuple] = []
        candidate_audits: list[tuple] = []
        ai_config = AIConfig()

        def audit():
            checkpoint()
            if verify_snapshot(store, sid)['manifest_sha256'] != verified['manifest_sha256']:
                raise PolicyError('Source snapshot changed during research')
            for receipt, proposal, sha in ai_audits:
                if _audit_ai_receipt(folder / 'calls', receipt, proposal, ai_config) != sha:
                    raise PolicyError('AI receipt changed during research')
            for path, sha in candidate_audits:
                if _sha(path.read_bytes()) != sha:
                    raise PolicyError('Saved candidate changed during research')
            if len({(s.get('image_id'), s.get('target_image_id'))
                    for s in result['stages'].values()}) > 1:
                raise PolicyError('Docker images differed between stages')
            for name, stage in result['stages'].items():
                if stage.get('cleanup') != 'PASS':
                    raise PolicyError('Independent cleanup failed: ' + name)
                if json.loads((folder / name / 'summary.json').read_text('utf-8')) != stage:
                    raise PolicyError('Independent stage summary changed: ' + name)

        def ask_validated(request_value, validator, stage, assist=None):
            """One model decision with bounded corrective repeats on format errors.

            Rejection ladder: first a targeted assist (red only: auto-probe the
            model's own unobserved hypothesis pairs and re-ask with the fresh
            observations), then the plain corrective repeat. Adapter-level
            ProposalRejected (worker-side double rejection, live run #5) also
            gets the assist before propagating, so the red loop can spend the
            decision and continue instead of killing the run.
            """
            emit(stage, 'wait_model', 'Ожидаем ответ модели.')
            req = request_value
            attempt = 0
            assisted = False
            while True:
                attempt += 1
                try:
                    proposal, receipt = adapter.ask(
                        req, **({'stop': stop} if stop is not None else {}))
                except ProposalRejected as exc:
                    result['ai_calls'].append({'role': req['role'], 'rejected': True,
                                               'reason': str(exc)[:300],
                                               **({'id': exc.receipt_id} if exc.receipt_id else {})})
                    if assist is not None and not assisted:
                        assisted_req = assist(req, exc.proposal, exc)
                        if assisted_req is not None:
                            assisted = True
                            req = assisted_req
                            emit(stage, 'wait_model',
                                 'Корректирующая попытка после автопроверки путей гипотез.')
                            continue
                    raise
                try:
                    validator(req, proposal)
                    return proposal, receipt
                except PolicyError as exc:
                    result['ai_calls'].append({'role': req['role'], 'id': receipt['id'],
                                               'rejected': True, 'reason': str(exc)[:300]})
                    if assist is not None and not assisted:
                        assisted_req = assist(req, proposal, exc)
                        if assisted_req is not None:
                            assisted = True
                            req = assisted_req
                            emit(stage, 'wait_model',
                                 'Корректирующая попытка после автопроверки путей гипотез.')
                            continue
                    if attempt >= 2:
                        raise PolicyError('Формат ответа модели отклонён дважды: '
                                          + str(exc)[:900]) from exc
                    req = contract.retry_request(req, str(exc)[:1500])

        (store.root / 'ai').mkdir(exist_ok=True)
        with worker_lock(store.root / 'ai'):
            checkpoint()
            emit('prepare', 'done', 'Подготовка и совместимость проекта проверены; '
                                    'исходный снимок не изменяется.')
            adapter = adapter_factory(Path.cwd(), folder / 'calls')
            ai_config = getattr(adapter, 'config', AIConfig())
            result['ai_config'] = ai_config.data()
            result['ai_config_sha256'] = ai_config.sha256
            history: list[dict] = []
            hypotheses: list[dict] = []

            def red_assist(bad_req, proposal, exc):
                """Auto-probe the model's own unobserved hypothesis pairs.

                Live run #5 died on 'Hypothesis must reference an HTTP
                observation' even though probing worked: the model hypothesized
                about pairs it had not probed, twice, and the run stopped. The
                core probes exactly those pairs through the ordinary independent
                observation stage (budget-checked, once per decision) and hands
                back a retry request whose history carries the observations.
                """
                if not isinstance(proposal, dict) or proposal.get('action') != 'hypotheses':
                    return None
                rows = proposal.get('hypotheses')
                if not isinstance(rows, list):
                    return None
                observed = {(o['path'], o['actor'])
                            for o in contract.observed_pairs(bad_req['history'])}
                planned, planned_keys = [], set()
                for row in rows:
                    if not isinstance(row, dict):
                        return None  # malformed reply: leave it to the corrective note
                    path, actor = row.get('path'), row.get('actor')
                    key = (path, actor)
                    if key in observed or key in planned_keys:
                        continue
                    if not isinstance(path, str) or not contract._PATH.fullmatch(path) or \
                            path.startswith('//') or '/..' in path or \
                            not (actor is None or (isinstance(actor, str)
                                                   and actor in bad_req['actors'])):
                        continue  # invalid pairs are the validator's job to explain
                    planned.append({'path': path, 'actor': actor})
                    planned_keys.add(key)
                    if len(planned) >= contract.HTTP_BATCH:
                        break
                if not planned:
                    return None
                remaining = budget.total['requests'] - budget.requests
                if remaining <= 0 or budget.total['seconds'] - budget.seconds_used < \
                        contract.VERIFIER_MIN_SECONDS:
                    result['notes'].append('Автопроверка путей гипотез пропущена: '
                                           'исчерпан бюджет HTTP-запросов.')
                    return None
                checks = [{'path': p['path'], 'actor': p['actor'], 'expected_status': 200}
                          for p in planned[:max(1, remaining)]]
                n = budget.decisions + 1
                stage_dir = folder / f'http_assist_{n:02d}'
                emit('red', 'running', 'Автопроверка путей из отклонённых гипотез: '
                                        '%d запрос(ов).' % len(checks))
                try:
                    observed_batch = _http_observe(stage_dir, identity, payload, checks, sid,
                                                   service, entry, verified, broker_factory,
                                                   observer, limits, stop)
                except (PolicyError, OSError, ValueError, KeyError, TypeError) as probe_exc:
                    result['notes'].append('Автопроверка путей гипотез не удалась: '
                                           + str(probe_exc)[:300])
                    return None
                budget.requests += len(checks)
                for check, obs in zip(checks, observed_batch['observations']):
                    observed_raw.append({'path': obs['path'], 'actor': obs['actor'],
                                         'actual_status': obs['actual_status'],
                                         'body_sha256': obs.get('body_sha256'),
                                         'body_bytes': obs.get('body_bytes'),
                                         'body_truncated': obs.get('body_truncated'),
                                         'stage': stage_dir.name, 'decision': n})
                result['stages'][stage_dir.name] = {
                    'stage': stage_dir.name, 'status': observed_batch['status'],
                    'observations': observed_batch['observations'],
                    'image_id': observed_batch['image_id'],
                    'target_image_id': observed_batch['target_image_id'],
                    'cleanup': observed_batch['cleanup'],
                    'receipt_sha256': observed_batch['receipt_sha256']}
                model_result = {'observations': [
                    {'path': o['path'], 'actor': o['actor'], 'status': o['actual_status']}
                    for o in observed_batch['observations']],
                    'batch_size': len(checks),
                    'note': 'Автопроверка пар из отклонённой гипотезы; '
                            'используйте эти наблюдения в гипотезах.'}
                hist = list(bad_req['history'])
                while len(hist) + 1 > contract.MAX_TURNS and hist:
                    drop = next((i for i, r in enumerate(hist)
                                 if not (isinstance(r.get('result'), dict)
                                         and 'observations' in r['result'])), 0)
                    hist.pop(drop)
                extended = dict(bad_req, history=hist + [
                    {'n': n, 'action': 'http_assist', 'result': model_result}])
                if len(checks) < len(planned):
                    result['notes'].append('Автопроверка покрыла %d из %d пар: '
                                           'лимит запросов.' % (len(checks), len(planned)))
                note = contract.assist_retry_note(checks)
                try:
                    return contract.retry_request(extended, note)
                except PolicyError:
                    try:
                        return contract.retry_request(contract.compact_request(extended), note)
                    except PolicyError as compact_exc:
                        result['notes'].append('Автопроверка выполнена, но расширенный запрос '
                                               'не помещается в транспортный бюджет: '
                                               + str(compact_exc)[:200])
                        return None

            # --- Red: self-directed study loop ---
            stop_reason = None
            decisions_total = budget.total['decisions']
            consecutive_rejected = 0
            while budget.decisions < decisions_total:
                checkpoint()
                if budget.seconds_used >= budget.total['seconds']:
                    stop_reason = 'budget_seconds_exhausted'
                    result['notes'].append('Время исследования исчерпано; цикл завершён по '
                                           'бюджету, накопленные результаты сохранены.')
                    break
                n = budget.decisions + 1
                emit('red', 'wait_model', f'Red · решение {n}/{decisions_total}; ожидаем ответ.')
                draft = dict(task=contract.TASK_RED, schema_version=1, role='red',
                             entry=relative, map=_compact_map(mapping),
                             knowledge=knowledge_text, history=history,
                             budget=budget.note(), actors=sorted(actors))
                req = contract.compact_request(draft)
                contract.validate_request(req)
                try:
                    proposal, receipt = ask_validated(req, contract.validate_reply, 'red',
                                                      assist=red_assist)
                except PolicyError as exc:
                    # Recoverable Red failures: a worker-side double rejection
                    # (ProposalRejected, live run #5) or a validator-side double
                    # rejection. The decision is spent, the reason lands in the
                    # model-visible history, and the loop continues; two rejected
                    # decisions in a row still stop the run (a persistently
                    # non-compliant model must not burn the whole budget).
                    if not (isinstance(exc, ProposalRejected)
                            or str(exc).startswith('Формат ответа модели')):
                        raise
                    budget.decisions += 1
                    consecutive_rejected += 1
                    result['notes'].append('Решение %d отклонено валидатором дважды: %s'
                                           % (n, str(exc)[:400]))
                    emit('red', 'error', 'Ответ модели отклонён повторно; решение потрачено, '
                                         'причина добавлена в историю, цикл продолжается.')
                    model_result = {'error': 'response rejected twice by contract validation',
                                    'reason': str(exc)[:900],
                                    'hint': 'Return exactly one prescribed JSON object per the '
                                            'rules; hypotheses may only use OBSERVED HTTP '
                                            'CHECKS pairs.'}
                    history.append({'n': n, 'action': 'rejected_response',
                                    'result': model_result})
                    atomic_text(folder / f'decision_{n:02d}.json', json.dumps(
                        {'decision': n, 'action': {'rejected': True, 'reason': str(exc)[:900]},
                         'result': model_result}, ensure_ascii=False, indent=2))
                    if consecutive_rejected >= 2:
                        raise PolicyError('Формат ответа модели отклонён в двух решениях '
                                          'подряд (%d); выполнение остановлено, накопленные '
                                          'результаты сохранены.' % n) from exc
                    continue
                budget.decisions += 1
                consecutive_rejected = 0
                result['ai_calls'].append({'role': 'red', 'id': receipt['id'],
                                           'model_digest': receipt['response']['model_digest']})
                ai_audits.append((receipt, proposal,
                                  _audit_ai_receipt(folder / 'calls', receipt, proposal,
                                                    ai_config)))
                action = proposal.get('action')
                if action is None:
                    # Live run #7 (dashboard): the model's admitted final response was
                    # {"hypotheses": [...]} without "action"; validate_reply admits that
                    # shape, so the loop must treat it as hypotheses instead of dying
                    # with KeyError('action') (dashboard showed "Причина: 'action'").
                    if 'hypotheses' not in proposal:
                        raise PolicyError('Admitted red proposal has neither action '
                                          'nor hypotheses')
                    action = 'hypotheses'
                if action == 'hypotheses':
                    hypotheses = proposal['hypotheses']
                    model_result = {'count': len(hypotheses)}
                    history.append({'n': n, 'action': action, 'result': model_result})
                    atomic_text(folder / f'decision_{n:02d}.json', json.dumps(
                        {'decision': n, 'action': proposal, 'result': model_result},
                        ensure_ascii=False, indent=2))
                    if proposal.get('note'):
                        result['notes'].append('Red: ' + proposal['note'][:1000])
                    break
                if action == 'read':
                    emit('red', 'running', f'Red читает {proposal["file"]}:{proposal["start"]}')
                    lines = sources[proposal['file']].splitlines()
                    start = proposal['start'] - 1
                    if start >= len(lines) and lines:
                        raise PolicyError('Read start exceeds source length')
                    text = '\n'.join(f'{i + 1}: {line}' for i, line in enumerate(lines)
                                     if start <= i < start + proposal['count'])
                    if len(text.encode('utf-8')) > contract.MAX_READ_BYTES:
                        raise PolicyError('Read excerpt exceeds 4500 bytes; choose smaller range')
                    model_result = {'file': proposal['file'], 'start': proposal['start'],
                                    'count': proposal['count'], 'text': text,
                                    'total_lines': len(lines)}
                elif action == 'search':
                    emit('red', 'running', f'Red ищет: {proposal["query"][:40]}')
                    matches = [{'file': path, 'line': i, 'text': line[:180]}
                               for path, source in sorted(sources.items())
                               for i, line in enumerate(source.splitlines(), 1)
                               if proposal['query'] in line]
                    model_result = {'query': proposal['query'],
                                    'matches': matches[:contract.MAX_SEARCH_MATCHES],
                                    'total_matches': len(matches),
                                    'truncated': len(matches) > contract.MAX_SEARCH_MATCHES}
                else:
                    remaining = budget.total['requests'] - budget.requests
                    if remaining <= 0:
                        model_result = {'error': 'HTTP budget exhausted; '
                                                 'use read/search or finish'}
                    elif budget.total['seconds'] - budget.seconds_used < \
                            contract.VERIFIER_MIN_SECONDS:
                        stop_reason = 'budget_seconds_exhausted'
                        model_result = {'error': 'Not enough time budget for HTTP probes; '
                                                 'finish or use read/search'}
                    else:
                        checks = [{'path': c['path'], 'actor': c['actor'],
                                   'expected_status': 200}
                                  for c in proposal['checks'][:max(1, remaining)]]
                        emit('red', 'running', f'Независимое HTTP-наблюдение: '
                                               f'{len(checks)} запрос(ов) в подготовленном стенде.')
                        stage_dir = folder / f'http_{n:02d}'
                        observed = _http_observe(stage_dir, identity, payload, checks, sid,
                                                 service, entry, verified, broker_factory,
                                                 observer, limits, stop)
                        budget.requests += len(checks)
                        for check, obs in zip(checks, observed['observations']):
                            observed_raw.append(
                                {'path': obs['path'], 'actor': obs['actor'],
                                 'actual_status': obs['actual_status'],
                                 'body_sha256': obs.get('body_sha256'),
                                 'body_bytes': obs.get('body_bytes'),
                                 'body_truncated': obs.get('body_truncated'),
                                 'stage': stage_dir.name, 'decision': n})
                        model_result = {'observations': [
                            {'path': o['path'], 'actor': o['actor'],
                             'status': o['actual_status']} for o in observed['observations']],
                            'batch_size': len(checks)}
                        if len(checks) < len(proposal['checks']):
                            model_result['note'] = 'Часть проверок не выполнена: лимит запросов'
                        result['stages'][stage_dir.name] = {
                            'stage': stage_dir.name, 'status': observed['status'],
                            'observations': observed['observations'],
                            'image_id': observed['image_id'],
                            'target_image_id': observed['target_image_id'],
                            'cleanup': observed['cleanup'],
                            'receipt_sha256': observed['receipt_sha256']}
                history.append({'n': n, 'action': action, 'result': model_result})
                atomic_text(folder / f'decision_{n:02d}.json', json.dumps(
                    {'decision': n, 'action': proposal, 'result': model_result,
                     'raw_observations': [o for o in observed_raw if o['decision'] == n]},
                    ensure_ascii=False, indent=2))
            else:
                stop_reason = 'budget_decisions_exhausted'
                result['notes'].append('Лимит решений модели исчерпан; накопленные '
                                       'результаты сохранены.')
            if not hypotheses and stop_reason is None:
                stop_reason = 'red_finished_without_hypotheses'
            result['coverage'] = budget.coverage()
            emit('red', 'done', 'Red завершена. Гипотез: %d; HTTP-наблюдений: %d.' %
                 (len(hypotheses), len(observed_raw)))

            # --- Classify hypotheses against Red's own observations ---
            raw_index: dict = {}
            for obs in observed_raw:
                raw_index.setdefault((obs['path'], obs['actor']), obs)
            candidates: list[tuple] = []
            for i, h in enumerate(hypotheses, 1):
                raw = raw_index.get((h['path'], h['actor']))
                row = dict(h, n=i, state='insufficient', observed_status=None,
                           confirm_status=None, observed_stage=None, confirm_stage=None)
                if raw is not None:
                    # Stage identifiers for the dashboard: which independent stand
                    # produced the Red observation, and which fresh stand (if any)
                    # re-checked it. Run #6 UI: 'Свежий стенд' showed a bare dash for
                    # consistent hypotheses because no fresh stand had run at all.
                    row['observed_status'] = raw['actual_status']
                    row['observed_stage'] = raw.get('stage')
                    row['state'] = ('consistent' if raw['actual_status'] == h['expected_status']
                                    else 'unconfirmed')
                result['hypotheses'].append(row)
                if row['state'] == 'unconfirmed':
                    candidates.append((row, raw))
            if not candidates:
                result['status'] = 'DONE'
                result['stop_reason'] = stop_reason or 'no_violation_hypotheses'
                result['notes'].append('Подтверждённых нарушений нет; безопасность приложения '
                                       'не оценена (полнота исследования не гарантируется).')
                return result

            # --- Independent confirmation on a fresh stand ---
            checkpoint()
            emit('confirm', 'running', 'Независимое воспроизведение на свежем стенде.')
            confirm_checks = [{'path': row['path'], 'actor': row['actor'],
                               'expected_status': raw['actual_status']}
                              for row, raw in candidates]
            confirm_dir = folder / 'confirm'
            confirm = _http_observe(confirm_dir, identity, payload, confirm_checks, sid,
                                    service, entry, verified, broker_factory, observer,
                                    limits, stop)
            budget.verifier_requests += len(confirm_checks)
            result['stages']['confirm'] = {'stage': 'confirm', 'status': confirm['status'],
                                           'observations': confirm['observations'],
                                           'image_id': confirm['image_id'],
                                           'target_image_id': confirm['target_image_id'],
                                           'cleanup': confirm['cleanup'],
                                           'receipt_sha256': confirm['receipt_sha256']}
            for (row, raw), obs in zip(candidates, confirm['observations']):
                row['confirm_status'] = obs['actual_status']
                row['confirm_stage'] = confirm_dir.name
                row['state'] = 'confirmed' if obs['actual_status'] == raw['actual_status'] \
                    else 'refuted'
            emit('confirm', 'done', 'Подтверждено: %d; опровергнуто: %d.' % (
                sum(1 for r, _ in candidates if r['state'] == 'confirmed'),
                sum(1 for r, _ in candidates if r['state'] == 'refuted')))
            audit()
            confirmed = [(row, raw) for row, raw in candidates if row['state'] == 'confirmed']
            if not confirmed:
                result['status'] = 'DONE'
                result['stop_reason'] = 'no_reproduced_violations'
                result['notes'].append('Ни одно нарушение не воспроизвелось на свежем стенде; '
                                       'безопасность не оценена.')
                return result
            result['finding_status'] = 'REPRODUCED'
            result['security_verdict'] = 'POLICY_VIOLATION_OBSERVED'

            # --- Blue: patch only what the independent verifier can re-check ---
            patchable, skipped = [], []
            for row, raw in confirmed:
                reason = None
                if row['expected_status'] not in contract.DENY_EXPECTED:
                    reason = ('ожидаемый статус %s не поддерживается автоисправлением'
                              % row['expected_status'])
                elif _control_anchor(raw_index, row) is None:
                    reason = 'нет зафиксированного разрешённого ответа 200 для контроля'
                if reason:
                    row['patch'] = 'SKIPPED: ' + reason
                    skipped.append(row)
                else:
                    patchable.append((row, raw))
            if skipped:
                result['notes'].append('Без автоисправления: ' + '; '.join(
                    '%s (%s)' % (r['path'], r['patch'][9:]) for r in skipped))
            if not patchable:
                result['status'] = 'NEEDS_REVIEW'
                result['stop_reason'] = 'confirmed_but_not_auto_patchable'
                result['notes'].append('Подтверждённые нарушения сохранены; автоматическое '
                                       'исправление неприменимо. Исходный проект не изменён.')
                return result
            if len(patchable) > contract.MAX_BLUE_PROBLEMS:
                result['notes'].append('Передано Blue первых %d проблем: лимит на цикл.'
                                       % contract.MAX_BLUE_PROBLEMS)
                for row, _ in patchable[contract.MAX_BLUE_PROBLEMS:]:
                    row['patch'] = 'SKIPPED: лимит проблем на цикл'
                patchable = patchable[:contract.MAX_BLUE_PROBLEMS]

            problems = [{'id': 'deny-%d' % (i + 1), 'file': row['file'], 'path': row['path'],
                         'actor': row['actor'], 'expected_status': row['expected_status'],
                         'observed_status': raw['actual_status'],
                         'description': row['description'], 'basis': row['basis']}
                        for i, (row, raw) in enumerate(patchable)]
            policies = [_blue_policy(i, row, raw, raw_index, identity)
                        for i, (row, raw) in enumerate(patchable, 1)]
            blue_files_paths = sorted({p['file'] for p in problems})
            blue_files = {p: sources[p] for p in blue_files_paths}
            try:
                observations_summary = [{'path': o['path'], 'actor': o['actor'],
                                         'actual_status': o['actual_status']}
                                        for o in observed_raw]
                blue_req = contract.make_blue_request(relative, blue_files, problems,
                                                      knowledge_text, observations_summary)
            except PolicyError as exc:
                result['status'] = 'NEEDS_REVIEW'
                result['stop_reason'] = 'blue_context_too_large'
                result['notes'].append('Исходники проблемы превышают лимит Blue (%s); '
                                       'исправление не запускалось. Нарушения подтверждены.'
                                       % str(exc)[:300])
                return result

            # Baseline: reproduce the confirmed violations against the blue policy.
            checkpoint()
            emit('baseline', 'running', 'Независимое воспроизведение подтверждённых нарушений.')
            baseline_ok = True
            for index, policy in enumerate(policies):
                name = 'baseline' if index == 0 else 'baseline_%d' % (index + 1)
                budget.verifier_requests += len(policy['checks'])
                report = _observe(store, folder, identity, name, sid, service, entry, module,
                                  sources, policy, _jsonsha(policy),
                                  verified['manifest_sha256'], broker_factory, observer,
                                  limits, stop, profile=contract.PROFILE)
                result['stages'][name] = report
                ok = report['status'] == 'ACCESS_POLICY_VIOLATION_REPRODUCED'
                baseline_ok = baseline_ok and ok
                emit(name, 'done' if ok else 'error', report['status'])
            audit()
            if not baseline_ok:
                result['status'] = 'NEEDS_REVIEW'
                result['stop_reason'] = 'baseline_not_reproduced'
                result['notes'].append('Исходное поведение не совпало с наблюдением Red '
                                       'при проверке плана исправления. Нарушения подтверждены, '
                                       'автоисправление остановлено.')
                return result

            repo, branch, base_commit = _prepare_git(folder, sources, relative, identity)
            patched = dict(sources)
            feedback_text = ''
            attempt_number = 0
            for attempt_number in (1, 2):
                checkpoint()
                audit()
                attempt_req = blue_req if attempt_number == 1 else contract.retry_request(
                    blue_req, feedback_text)
                proposal, receipt = ask_validated(attempt_req, contract.validate_blue_reply,
                                                  'blue_%d' % attempt_number)
                attempt = receipt.get('attempt')
                if type(attempt) is not int or attempt not in (1, 2) or \
                        (attempt_number == 2 and attempt != 2):
                    raise PolicyError('Invalid Blue attempt budget receipt')
                result['ai_calls'].append({'role': 'blue', 'id': receipt['id'],
                                           'model_digest': receipt['response']['model_digest']})
                ai_audits.append((receipt, proposal,
                                  _audit_ai_receipt(folder / 'calls', receipt, proposal,
                                                    ai_config)))
                candidate_error = None
                try:
                    patched = dict(sources, **proposal['files'])
                    app_map.inventory(patched, relative)
                except (PolicyError, ValueError, SyntaxError) as exc:
                    candidate_error = ('Кандидат нарушает поддерживаемый профиль приложения: '
                                       + str(exc)[:600])
                if candidate_error is None:
                    changed_paths = [p for p in sorted(sources) if patched[p] != sources[p]]
                    encoded = json.dumps(patched, ensure_ascii=False, sort_keys=True)
                    candidate_file = folder / f'candidate_{attempt_number}.json'
                    atomic_text(candidate_file, encoded)
                    candidate_audits.append((candidate_file, _sha(encoded)))
                    patch_text = ''.join(
                        line if line.endswith('\n') else line + '\n\\ No newline at end of file\n'
                        for p in changed_paths
                        for line in difflib.unified_diff(sources[p].splitlines(keepends=True),
                                                         patched[p].splitlines(keepends=True),
                                                         fromfile='a/' + p, tofile='b/' + p))
                    atomic_text(folder / f'candidate_{attempt_number}.patch', patch_text)
                    result['candidates'].append({'file': candidate_file.name,
                                                 'sha256': _sha(encoded),
                                                 'changed_files': changed_paths,
                                                 'call_id': receipt['id']})
                    for p, content in patched.items():
                        safe_path(repo, p).write_bytes(content.encode('utf-8'))
                    _git(repo, 'diff', '--check')
                    if set(_git(repo, 'diff', '--name-only').splitlines()) != set(changed_paths):
                        raise PolicyError('Patch attempted to modify an unselected file')
                    stage = 'candidate' if attempt_number == 1 else 'candidate_retry'
                    matched = True
                    for index, policy in enumerate(policies):
                        audit()
                        name = stage if index == 0 else '%s_%d' % (stage, index + 1)
                        budget.verifier_requests += len(policy['checks'])
                        emit(name, 'running', 'Независимая проверка кандидата, пакет %d/%d.'
                             % (index + 1, len(policies)))
                        report = _observe(store, folder, identity, name, sid, service, entry,
                                          module, patched, policy, _jsonsha(policy),
                                          verified['manifest_sha256'], broker_factory, observer,
                                          limits, stop, profile=contract.PROFILE)
                        result['stages'][name] = report
                        matched = matched and report['status'] == 'ACCESS_POLICY_MATCHED'
                        emit(name, 'done' if matched else 'error', report['status'])
                    if matched:
                        break
                    candidate_error = 'Кандидат не прошёл независимую проверку политики доступа'
                if attempt_number == 2:
                    result['status'] = 'NEEDS_REVIEW'
                    result['stop_reason'] = 'patch_not_verified'
                    result['notes'].append('Blue не дал проверяемого исправления: '
                                           + str(candidate_error)[:600])
                    return result
                evidence = [{'path': p['path'], 'expected_status': p['expected_status'],
                             'observed_status': p['observed_status']} for p in problems]
                feedback_text = json.dumps({'error': candidate_error, 'problems': evidence},
                                           ensure_ascii=False)[:4000]
                emit('blue_%d' % attempt_number, 'error',
                     'Кандидат %d отклонён независимой проверкой; подготовлена корректирующая '
                     'попытка.' % attempt_number)
            checkpoint()
            audit()
            # --- Recheck on fresh stands ---
            emit('recheck', 'running', 'Повторная проверка на свежем стенде.')
            recheck_ok = True
            for index, policy in enumerate(policies):
                name = 'recheck' if index == 0 else 'recheck_%d' % (index + 1)
                budget.verifier_requests += len(policy['checks'])
                report = _observe(store, folder, identity, name, sid, service, entry, module,
                                  patched, policy, _jsonsha(policy),
                                  verified['manifest_sha256'], broker_factory, observer,
                                  limits, stop, profile=contract.PROFILE)
                result['stages'][name] = report
                recheck_ok = recheck_ok and report['status'] == 'ACCESS_POLICY_MATCHED'
            emit('recheck', 'done' if recheck_ok else 'error',
                 'Повторная проверка пройдена' if recheck_ok
                 else 'Повторная проверка не пройдена')
            if not recheck_ok:
                result['status'] = 'NEEDS_REVIEW'
                result['stop_reason'] = 'recheck_failed'
                result['notes'].append('Повторная независимая проверка не подтвердила патч.')
                return result
            for p, content in patched.items():
                if safe_path(repo, p).read_bytes() != content.encode('utf-8'):
                    raise PolicyError('Candidate Git workspace changed during verification')
            if _git(repo, 'rev-parse', 'main') != base_commit or \
                    _git(repo, 'branch', '--show-current') != branch:
                raise PolicyError('Git baseline or work branch changed')
            checkpoint()
            emit('commit', 'running', 'Фиксация проверенного патча в изолированном Git; без merge.')
            _git(repo, 'add', '--', *sorted(patched))
            _git(repo, 'commit', '-q', '-m', 'SecurityLab research patch: independently rechecked')
            head = _git(repo, 'rev-parse', 'HEAD')
            if head == base_commit or _git(repo, 'status', '--porcelain'):
                raise PolicyError('Isolated Git commit not clean or not distinct')
            result['git'] = {'directory': str(repo), 'branch': branch,
                             'base_commit': base_commit, 'verified_commit': head,
                             'diff': _git(repo, 'diff', 'main..HEAD', '--', *sorted(patched)),
                             'source_repository_modified': False, 'merged': False}
            emit('commit', 'done', 'Патч сохранён в изолированном репозитории.')
            result['status'] = 'PASS'
            result['finding_status'] = 'FIXED'
            result['security_verdict'] = 'POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX'
            result['stop_reason'] = 'completed'
    except KeyboardInterrupt:
        result.update(status='STOPPED' if cleanup_confirmed() else 'BLOCKED',
                      error='Stopped by operator; see cleanup receipts')
        result['stop_reason'] = 'cancelled'
    except (PolicyError, OSError, KeyError, ValueError, TypeError, IndexError) as exc:
        cancelled = stop is not None and stop()
        result.update(status='STOPPED' if cancelled and cleanup_confirmed() else 'BLOCKED',
                      error=str(exc)[:2000])
        if cancelled:
            result['stop_reason'] = 'cancelled'
            result['cleanup'] = 'PASS' if cleanup_confirmed() else 'FAIL'
    finally:
        if budget is not None:
            result['coverage'] = budget.coverage()
        atomic_text(folder / 'summary.json', json.dumps(result, ensure_ascii=False, indent=2))
    return result


def _control_anchor(raw_index, row):
    for (path, actor), obs in sorted(raw_index.items()):
        if (path == row['path'] and actor is not None and actor != row['actor'] and
                obs['actual_status'] == 200 and obs['body_bytes'] and obs['body_bytes'] > 0 and
                not obs['body_truncated'] and obs['body_sha256']):
            return obs
    return None


def _blue_policy(index, row, raw, raw_index, identity) -> dict:
    anchor = _control_anchor(raw_index, row)
    checks = [{'id': 'control-%d' % index, 'kind': 'control', 'path': row['path'],
               'actor': anchor['actor'], 'expected_status': 200,
               'expected_body_sha256': anchor['body_sha256']}]
    extra = 0
    for (path, actor), obs in sorted(raw_index.items()):
        if (path == row['path'] and actor is not None and actor != row['actor'] and
                actor != anchor['actor'] and obs['actual_status'] == 200 and
                obs['body_bytes'] and obs['body_bytes'] > 0 and not obs['body_truncated'] and
                obs['body_sha256'] and len(checks) < contract.HTTP_BATCH - 1):
            extra += 1
            checks.append({'id': 'allowed-%d-%d' % (index, extra), 'kind': 'control',
                           'path': row['path'], 'actor': actor, 'expected_status': 200,
                           'expected_body_sha256': obs['body_sha256']})
    checks.append({'id': 'deny-%d' % index, 'kind': 'deny', 'path': row['path'],
                   'actor': row['actor'], 'expected_status': row['expected_status'],
                   'compare_body_to': 'control-%d' % index})
    policy = {'schema_version': 2, 'policy_id': 'research-%s' % identity[:12], 'checks': checks}
    validate_policy(policy)
    return policy


def _http_observe(stage_dir: Path, run_id: str, payload: bytes, checks: list, sid: str,
                  service: str, entry: str, verified: dict, broker_factory, observer,
                  limits, stop) -> dict:
    batch_hash = hashlib.sha256(json.dumps(
        [[c['path'], c['actor']] for c in checks], separators=(',', ':')).encode()).hexdigest()
    binding = {'run_id': run_id, 'stage': stage_dir.name, 'snapshot_id': sid,
               'service': service, 'entry': entry,
               'manifest_sha256': verified['manifest_sha256'],
               'checks_binding_sha256': batch_hash, 'payload_sha256': _sha(payload),
               'profile': contract.PROFILE}
    observed = observer(stage_dir, payload, checks, binding, broker_factory=broker_factory,
                        limits=limits, **({'stop': stop} if stop is not None else {}))
    for check, obs in zip(checks, observed['observations']):
        if obs['path'] != check['path'] or obs['actor'] != check['actor']:
            raise PolicyError('Independent observation does not match requested check')
        if obs['actual_status'] is None:
            raise PolicyError('HTTP observation failed: ' + str(obs.get('error', 'no response')))
    stage_summary = {'stage': stage_dir.name, 'status': observed['status'],
                     'observations': observed['observations'], 'image_id': observed['image_id'],
                     'target_image_id': observed['target_image_id'],
                     'cleanup': observed['cleanup'],
                     'receipt_sha256': observed['receipt_sha256']}
    atomic_text(stage_dir / 'summary.json', json.dumps(stage_summary, ensure_ascii=False, indent=2))
    return observed
