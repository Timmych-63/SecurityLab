# SecurityLab S6.3b — ограниченная независимая проверка HTTP

**Основа:** установленная S6.3a. **Коммит:** `deafff0`.

S6.3a у пользователя прошёл на Windows: 12/12 тестов и реальный Docker probe
со статусом `EXECUTED_UNTRUSTED`, очисткой `PASS`.

S6.3b добавляет `repo http-probe`: выбранный Python-файл из проверенного
снимка запускается в одном Docker-контейнере, независимый HTTP-проверяющий
выполняется во втором. Оба работают во временной внутренней сети Docker,
без публикации портов на ПК, host mounts и доступа к Docker socket. Проверки
задаются через `--expect /path=200` и всегда остаются
`security_verdict: NOT_EVALUATED`. Это ещё не поиск уязвимостей и не FastAPI.

## Установка вручную, как раньше

Распаковать ZIP. В рабочей папке SecurityLab заменить:

- `securitylab/cli.py`
- `securitylab/profile_plan.py`

Добавить новые:

- `securitylab/http_probe.py`
- `securitylab/http_runner.py`
- `tests/test_http_probe.py`
- две папки из `examples/s6_repos`: `python_http_alpha` и `python_http_beta`.

Документы `docs/*` можно скопировать с заменой. **Не трогать** `.securitylab`,
том Ollama, Hermes, предыдущие исходники/модели и Git-конфигурацию пользователя.
Встроенный `container_worker` от S6.3a остаётся неизменным; образ Docker
пересобирать не требуется, если есть `securitylab-demo:local`.

## Проверка 1: Windows-тесты

```powershell
py -3 -m unittest discover -s tests -p test_http_probe.py -v
```

Ожидается 17 тестов `OK`. Из них реальный HTTP-тест использует только
доверенный тестовый localhost-сервер; **Docker в unit-тестах имитируется**.

## Проверка 2: реальный двухконтейнерный запуск на Windows

```powershell
$state = Join-Path $env:TEMP 'SecurityLab_S63b_DemoState'
$p = py -3 -m securitylab --state "$state" repo add '.\examples\s6_repos\python_http_alpha' --name 'HTTP alpha' | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo add failed' }
$s = py -3 -m securitylab --state "$state" repo snapshot $p.id | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'repo snapshot failed' }
py -3 -m securitylab --state "$state" repo verify-snapshot $s.snapshot_id
if ($LASTEXITCODE -ne 0) { throw 'verify-snapshot failed' }
py -3 -m securitylab --state "$state" repo http-probe $s.snapshot_id --entry main.py --expect '/health=200' --expect '/__missing__=404' --execute
```

Ожидается `HTTP_CHECKS_PASSED`, `cleanup=PASS`, `security_verdict=NOT_EVALUATED`.
Если получен `BLOCKED`, достаточно прислать JSON ответа и файл
`$state\http_probes\<run_id>\docker_receipt.json` **без секретов**.

Для проверки независимости от имён файлов и путей приложения можно затем
запустить `python_http_beta`: команды в `docs/S6_3b.md`.

## Что известно о проверках

- Локально 17 S6.3b + 12 S6.3a + 18 S6.2 + 22 S6.1 + 27 DockerBroker = **96 PASS**.
- Сквозная новая сеть/контейнеры/Windows: **ещё не проверено**.
- Полный старый AI-интеграционный набор: **в этой поставке не запускался**.
- Новая модель/Hermes: **не менялись**.
- S7 Red/Blue, настоящий FastAPI и произвольные репозитории: ещё впереди.

Полный Git bundle восстанавливает исходники в *новую* папку без overlays:
`git clone SecurityLab_S6_3b.bundle SecurityLab_Source`.
