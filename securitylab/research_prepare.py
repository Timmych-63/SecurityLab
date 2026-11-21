"""Research input preparation only: no model calls or target execution."""
import hashlib
import json
import time
from pathlib import Path
import uuid

from .access_baseline import _unique_pairs
from .app_map import inventory
from .package_probe import _member, _source_package
from .policy import PolicyError
from .storage import atomic_text

MAX_DOCUMENT_BYTES = 12 * 1024


def read_document(path):
    path = Path(path)
    # _member rechecks inode/stat and bytes after reading; never follows a leaf symlink.
    try:
        if path.is_symlink() or not path.is_file():
            raise PolicyError('Документ должен быть обычным файлом без ссылки')
        with path.open('rb') as stream:
            raw = stream.read(MAX_DOCUMENT_BYTES + 1)
        if not raw or len(raw) > MAX_DOCUMENT_BYTES:
            raise PolicyError('Документ должен содержать от 1 до 12288 байт')
        text = _member(path, {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    except (OSError, UnicodeError) as exc:
        raise PolicyError('Не удалось прочитать документ UTF-8') from exc
    return text, hashlib.sha256(raw).hexdigest()


def read_text_document(text, name):
    """Bounded inline input (dashboard upload path); same limits as files."""
    if not isinstance(text, str) or not 1 <= len(text.encode('utf-8')) <= MAX_DOCUMENT_BYTES:
        raise PolicyError(f'{name}: ожидается текст от 1 до 12288 байт')
    return text, hashlib.sha256(text.encode('utf-8')).hexdigest()


def validate_setup(value):
    required = {'schema_version', 'runtime', 'identity', 'actors', 'budget'}
    if not isinstance(value, dict) or set(value) != required:
        raise PolicyError('Настройки: нужны только schema_version, runtime, identity, actors, budget')
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise PolicyError('Неизвестная версия настроек')
    if value['runtime'] != 'fastapi-local-v1' or value['identity'] != 'trusted-test-user-header':
        raise PolicyError('Пока поддерживается локальный FastAPI с тестовой идентификацией')
    actors = value['actors']
    import re
    if not isinstance(actors, dict) or not 1 <= len(actors) <= 16 or any(
        not isinstance(k, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}', k)
        or not isinstance(v, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}', v)
        for k, v in actors.items()
    ):
        raise PolicyError('Нужны 1–16 тестовых аккаунтов с ролями; пароли сюда не помещаются')
    budget = value['budget']
    bounds = {'seconds': (60, 3600), 'decisions': (1, 30), 'requests': (1, 100)}
    if not isinstance(budget, dict) or set(budget) != set(bounds) or any(
        type(budget[k]) is not int or not lo <= budget[k] <= hi
        for k, (lo, hi) in bounds.items()
    ):
        raise PolicyError('Бюджет: seconds 60–3600, decisions 1–30, requests 1–100')
    return value


def prepare_research(store, snapshot_id, entry, knowledge=None, setup=None, service='.',
                     knowledge_text=None, setup_value=None):
    if knowledge_text is not None:
        markdown, knowledge_hash = read_text_document(knowledge_text, 'Описание приложения')
    else:
        markdown, knowledge_hash = read_document(knowledge)
    if setup_value is not None:
        config = validate_setup(setup_value)
        setup_text = json.dumps(config, ensure_ascii=False, indent=2) + '\n'
        setup_hash = hashlib.sha256(setup_text.encode('utf-8')).hexdigest()
    else:
        setup_text, setup_hash = read_document(setup)
        try:
            config = validate_setup(json.loads(setup_text, object_pairs_hook=_unique_pairs))
        except (ValueError, TypeError) as exc:
            raise PolicyError('Настройки должны быть корректным JSON') from exc
    module, files, package_hash, _, verified = _source_package(store, snapshot_id, service, entry)
    relative_entry = entry if service == '.' else entry[len(service) + 1:]
    mapping = inventory(files, relative_entry)
    identity = uuid.uuid4().hex
    folder = store.root / 'research_preparations' / identity
    result = {
        'schema_version': 1, 'id': identity, 'status': 'PREPARED',
        'execution_ready': False, 'security_verdict': 'NOT_EVALUATED',
        'created': time.time(),
        'snapshot_id': snapshot_id, 'entry': entry, 'service': service, 'module': module,
        'manifest_sha256': verified['manifest_sha256'], 'package_sha256': package_hash,
        'knowledge_sha256': knowledge_hash, 'setup_sha256': setup_hash,
        'runtime': config['runtime'], 'budget': config['budget'],
        'actors': dict(config['actors']),
        'capabilities': ['source.read', 'source.search', 'local.http.get'],
        'limitations': ['Подготовка не запускает Docker или AI и не подтверждает готовность стенда',
                        'Готовность стенда проверяется отдельно перед запуском (preflight)',
                        'До 31 Python-модуля / 180 КБ; статические маршруты; без внешних БД'],
        'record': str(folder / 'summary.json'),
    }
    folder.mkdir(parents=True, exist_ok=False)
    atomic_text(folder / 'knowledge.md', markdown)
    atomic_text(folder / 'setup.json', setup_text)
    atomic_text(folder / 'application_map.json', json.dumps(mapping, ensure_ascii=False, indent=2))
    atomic_text(folder / 'summary.json', json.dumps(result, ensure_ascii=False, indent=2))
    _supersede_previous(store, result)
    return result


def _supersede_previous(store, current):
    """Changing the inputs invalidates older preparations of the same snapshot/entry."""
    base = store.root / 'research_preparations'
    if not base.is_dir():
        return
    for path in sorted(base.glob('*/summary.json')):
        if path.parent.name == current['id']:
            continue
        try:
            saved = json.loads(path.read_text('utf-8'))
        except (OSError, ValueError):
            continue
        if (saved.get('status') == 'PREPARED' and
                saved.get('snapshot_id') == current['snapshot_id'] and
                saved.get('service') == current['service'] and
                saved.get('entry') == current['entry']):
            saved['status'] = 'SUPERSEDED'
            saved['superseded_by'] = current['id']
            saved['superseded_reason'] = ('Входные данные (документация или настройки) '
                                          'изменены; подготовлена новая версия')
            atomic_text(path, json.dumps(saved, ensure_ascii=False, indent=2))
