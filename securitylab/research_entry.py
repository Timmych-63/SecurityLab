"""S11.1: bounded dashboard intake and reproducible environment readiness.

No autonomous research runner is enabled here. Untrusted target code is never
executed by this module on the host; the startup check uses the pinned Docker
FastAPI broker through package_probe_snapshot.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tempfile
import time

from .app_map import inventory
from .package_probe import _source_package, package_probe_snapshot
from .policy import PolicyError, Limits
from .research_prepare import prepare_research, read_document, validate_setup
from .snapshots import verify_snapshot
from .storage import atomic_text
from .access_baseline import _unique_pairs

PREPARATION_ID = re.compile(r'[a-f0-9]{32}\Z', re.ASCII)
INPUT_KEYS = {'projectId', 'snapshotId', 'service', 'entry', 'knowledge', 'setupText', 'aiConfigId'}


def _read_json(path: Path, *, max_bytes: int = 32_768):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise PolicyError('Файл подготовки отсутствует или недопустим')
    return json.loads(path.read_bytes().decode('utf-8'), object_pairs_hook=_unique_pairs)


def _preparation_dir(store, preparation_id):
    if not isinstance(preparation_id, str) or not PREPARATION_ID.fullmatch(preparation_id):
        raise PolicyError('Некорректный идентификатор подготовки')
    return store.root / 'research_preparations' / preparation_id


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_research_preparation(store, payload, profiles):
    if (not isinstance(payload, dict) or set(payload) != INPUT_KEYS or
        any(not isinstance(value, str) for value in payload.values())):
        raise PolicyError('Неверные поля подготовки исследования')
    if not PREPARATION_ID.fullmatch(payload['projectId']) or not PREPARATION_ID.fullmatch(payload['snapshotId']):
        raise PolicyError('Некорректный проект или снимок')
    if not 1 <= len(payload['knowledge'].encode('utf-8')) <= 12_288 or not 1 <= len(payload['setupText'].encode('utf-8')) <= 12_288:
        raise PolicyError('Markdown и JSON должны содержать от 1 до 12288 байт каждый')
    config = profiles.get(payload['aiConfigId'])
    if not store.db.execute('SELECT 1 FROM project_snapshots WHERE id=? AND project_id=?',
                            (payload['snapshotId'], payload['projectId'])).fetchone():
        raise PolicyError('Снимок не принадлежит выбранному проекту')
    # Use the tested S11.0 reader, duplicate-key validation and snapshot
    # admission. Ephemeral user input is never interpreted as file paths.
    with tempfile.TemporaryDirectory(prefix='research-input-', dir=store.root) as staging:
        knowledge = Path(staging) / 'knowledge.md'
        setup = Path(staging) / 'setup.json'
        knowledge.write_text(payload['knowledge'], encoding='utf-8')
        setup.write_text(payload['setupText'], encoding='utf-8')
        result = prepare_research(store, payload['snapshotId'], payload['entry'],
                                  knowledge, setup, payload['service'])
    result.update(project_id=payload['projectId'], ai_config_id=payload['aiConfigId'],
                  ai_config_sha256=config.sha256)
    folder = _preparation_dir(store, result['id'])
    atomic_text(folder / 'summary.json', json.dumps(result, ensure_ascii=False, indent=2))
    return result


def load_research_preparation(store, preparation_id):
    folder = _preparation_dir(store, preparation_id)
    summary = _read_json(folder / 'summary.json')
    if (not isinstance(summary, dict) or summary.get('id') != preparation_id or
        summary.get('status') != 'PREPARED' or summary.get('execution_ready') is not False or
        summary.get('security_verdict') != 'NOT_EVALUATED'):
        raise PolicyError('Запись подготовки имеет некорректное состояние')
    return summary


def validate_research_binding(store, summary, profiles):
    folder = _preparation_dir(store, summary['id'])
    if not store.db.execute('SELECT 1 FROM project_snapshots WHERE id=? AND project_id=?',
                            (summary['snapshot_id'], summary.get('project_id'))).fetchone():
        raise PolicyError('Связь проекта со снимком изменена')
    text, h = read_document(folder / 'knowledge.md')
    setup_text, setup_h = read_document(folder / 'setup.json')
    if h != summary['knowledge_sha256'] or setup_h != summary['setup_sha256']:
        raise PolicyError('Документация или настройки изменены: требуется новая подготовка')
    try:
        validate_setup(json.loads(setup_text, object_pairs_hook=_unique_pairs))
    except (ValueError, TypeError) as exc:
        raise PolicyError('Настройки подготовки повреждены') from exc
    cfg = profiles.get(summary['ai_config_id'])
    if cfg.sha256 != summary['ai_config_sha256']:
        raise PolicyError('Параметры выбранной AI-модели изменились: требуется новая подготовка')
    module, files, package_hash, _, verified = _source_package(
        store, summary['snapshot_id'], summary['service'], summary['entry'])
    relative_entry = summary['entry'] if summary['service'] == '.' else summary['entry'][len(summary['service']) + 1:]
    mapping = inventory(files, relative_entry)
    if (module != summary['module'] or package_hash != summary['package_sha256'] or
        verified['manifest_sha256'] != summary['manifest_sha256'] or
        _read_json(folder / 'application_map.json', max_bytes=1_000_000) != mapping):
        raise PolicyError('Снимок или карта приложения изменены: требуется новая подготовка')
    return cfg


def list_research_preparations(store, profiles=None):
    parent = store.root / 'research_preparations'
    if not parent.exists():
        return []
    rows = []
    for folder in sorted(parent.iterdir(), key=lambda p: p.name, reverse=True):
        if not folder.is_dir() or folder.is_symlink() or not PREPARATION_ID.fullmatch(folder.name):
            continue
        try:
            r = load_research_preparation(store, folder.name)
            rows.append({k: r.get(k) for k in ('id','project_id','snapshot_id','entry','service','status','execution_ready','ai_config_id')})
            rows[-1]['preflight'] = 'NOT_CHECKED'
            path = folder / 'preflight.json'
            if path.exists():
                rows[-1]['preflight'] = _read_json(path).get('status', 'ERROR')
                # Historical PASS is not a present-time grant: validate every
                # binding before displaying a ready state in the catalog.
                if profiles is not None and rows[-1]['preflight'] == 'STAND_READY':
                    try:
                        validate_research_binding(store, r, profiles)
                    except (PolicyError, OSError, ValueError, KeyError, UnicodeError):
                        rows[-1]['preflight'] = 'STALE'
        except (PolicyError, OSError, KeyError, ValueError, UnicodeError):
            continue
        if len(rows) >= 100:
            break
    return rows


def research_preflight(store, preparation_id, profiles, docker_probe, model_probe, *, startup_probe=package_probe_snapshot):
    """Run explicit operator-requested checks, never mark a research run ready.

    docker_probe checks pinned images/daemon. startup_probe launches a *fresh*
    isolated Docker target and GET /openapi.json; this is a capability check,
    not a security verdict. The model probe checks identity/digest, not quality.
    """
    summary = load_research_preparation(store, preparation_id)
    folder = _preparation_dir(store, preparation_id)
    report = {'schema_version': 1, 'preparationId': preparation_id,
              'status': 'BLOCKED', 'environment_ready': False,
              'execution_ready': False, 'security_verdict': 'NOT_EVALUATED',
              'checks': [], 'checkedAt': time.time(), 'limits_enforced': False}
    def step(name, ok, detail):
        report['checks'].append({'name': name, 'status': 'PASS' if ok else 'BLOCKED',
                                 'detail': str(detail)[:1000]})
    try:
        cfg = validate_research_binding(store, summary, profiles)
        step('Снимок, Markdown, настройки и AI-профиль', True, 'Хеши и совместимость подтверждены')
        # The UI is not allowed to grant runtime permissions by editing Markdown.
        docker_probe()
        step('Docker и закреплённые образы', True, 'Docker доступен, admission образов пройдена')
        model_probe(cfg)
        step('Hermes и модель', True, 'Сверены модель и digest; генерация не проверена')
        probe = startup_probe(store, summary['snapshot_id'], summary['entry'], ['/openapi.json=200'],
                              service=summary['service'], execute=True, limits=Limits(timeout=60))
        if probe.get('status') != 'HTTP_CHECKS_PASSED' or probe.get('cleanup') != 'PASS':
            raise PolicyError('FastAPI /openapi.json не подтвердил запуск и очистку: ' +
                              str(probe.get('error') or probe.get('status', 'unknown')))
        # A preflight may take minutes; detect edits that happened *during* it.
        validate_research_binding(store, summary, profiles)
        step('Запуск приложения на свежем стенде', True, 'GET /openapi.json = 200, cleanup PASS')
        report.update(status='STAND_READY', environment_ready=True,
                      startup_probe_record=probe.get('record'),
                      input_binding_sha256=_sha256(json.dumps({
                          'project_id': summary['project_id'],
                          'snapshot_id': summary['snapshot_id'],
                          'manifest_sha256': summary['manifest_sha256'],
                          'package_sha256': summary['package_sha256'],
                          'knowledge_sha256': summary['knowledge_sha256'],
                          'setup_sha256': summary['setup_sha256'],
                          'ai_config_sha256': summary['ai_config_sha256'],
                      }, sort_keys=True).encode('utf-8')))
    except (PolicyError, OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
        step('Предпроверка', False, exc)
        report['reason'] = str(exc)[:1000]
    report['next'] = 'Цикл Red ещё не подключён; запуск исследования недоступен.'
    atomic_text(folder / 'preflight.json', json.dumps(report, ensure_ascii=False, indent=2))
    return report
