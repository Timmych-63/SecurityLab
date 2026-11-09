# SecurityLab S7.1 — независимая проверка политики доступа

Установка: обновление поверх **S6.3d**, которое уже успешно прошло на Windows пользователя.
Это ZIP-overlay, НЕ полноценный самостоятельный дистрибутив; полный исходный
код также есть в прилагаемом Git bundle.

## Изменённые файлы

- `securitylab/http_runner.py` — наблюдение синтетического `X-Test-User`,
  SHA-256 тела HTTP-ответа и проверка квитанций; старые GET-профили сохранены.
- `securitylab/access_baseline.py` — строго заданный человеком контракт,
  независимое сравнение контрольного ответа и чужого чтения.
- `securitylab/cli.py` — новая команда.
- `tests/test_access_baseline.py` — 17 тестов.
- `examples/s7_repos/authz_vulnerable/` и `authz_fixed/` — изолированные учебные API.
- `examples/security_policies/record_ownership.json` — отдельный эталон прав
  и заранее заданных SHA-256 контрольных HTTP-ответов.
- `docs/S7_1.md`, `docs/STATE.md`, `docs/CHANGELOG.md` — документация.

Распакуй ZIP. В рабочую папку SecurityLab перенеси новые/изменённые файлы
с сохранением путей (содержимое папок `securitylab`, `tests`, `examples`, `docs`).
Не удаляй `.securitylab`. Старые проекты, образы `demo`/`FastAPI`, Hermes,
Ollama и Qwen пересобирать/скачивать не нужно.

## Шаг 1. Unit-тесты

```powershell
py -3 -m unittest discover -s tests -p test_access_baseline.py -v
```

Ожидается `Ran 17 tests`, `OK`; тест с symlink может быть пропущен
при ограничениях Windows.

## Шаг 2. Воспроизвести ошибку на учебном примере

```powershell
$state = Join-Path $env:TEMP 'SecurityLab_S71_DemoState'
$policy = '.\examples\security_policies\record_ownership.json'

$p = py -3 -m securitylab --state "$state" repo add '.\examples\s7_repos\authz_vulnerable' --name 'S7 vulnerable synthetic' | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo add failed' }
$s = py -3 -m securitylab --state "$state" repo snapshot $p.id | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'snapshot failed' }

py -3 -m securitylab --state "$state" repo access-baseline $s.snapshot_id --entry app/main.py --policy "$policy" --execute
```

Ожидается `ACCESS_POLICY_VIOLATION_REPRODUCED`, `cleanup: PASS`,
`finding_status: REPRODUCED`; **код завершения 3 — намеренно: нарушение
политики обнаружено**, это не ошибка установки.

## Шаг 3. Проверить отдельно подготовленный исправленный пример

```powershell
$p2 = py -3 -m securitylab --state "$state" repo add '.\examples\s7_repos\authz_fixed' --name 'S7 fixed synthetic' | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo add fixed failed' }
$s2 = py -3 -m securitylab --state "$state" repo snapshot $p2.id | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'snapshot fixed failed' }

py -3 -m securitylab --state "$state" repo access-baseline $s2.snapshot_id --entry app/main.py --policy "$policy" --execute
```

Ожидается `ACCESS_POLICY_MATCHED`, `cleanup: PASS`, `security_verdict:
NOT_PROVEN_SAFE` — **не** `FIXED`. Это два заранее подготовленных примера,
а не выполненный полный Red/Blue-цикл.

Полные требования/ограничения: `docs/S7_1.md`.
