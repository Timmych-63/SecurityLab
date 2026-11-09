# SecurityLab S6.2 — обновление (копия проекта и проверка хешей)

**Основа:** установленная S6.1 (`e2ffcd3`), которая уже прошла у пользователя
Windows-проверку: 22 теста, 1 ожидаемый skip на Windows; `repo inspect` работает.
Новая S6.2 не запускает модель, не пересобирает Docker и не изменяет существующую
папку `.securitylab` при установке overlay.

## Установка обычной распаковкой (как в S6.1)

Скачайте ZIP, распакуйте в отдельную папку. Из неё скопируйте **с заменой**:

- `securitylab/cli.py`, `storage.py`, `repository.py`, `snapshots.py`, `profile_plan.py`
  в существующую папку `securitylab/`.
- `tests/test_snapshots.py` в `tests/`.

Остальные файлы (документация, Git bundle) не нужны для работы команд.
Не копируйте извлечённую `.securitylab` (её нет в архиве), не удаляйте старую
`.securitylab`, не трогайте контейнер с Ollama и модель.

## Проверка на Windows (PowerShell в корне SecurityLab)

```powershell
py -3 -m unittest discover -s tests -p test_snapshots.py -v
py -3 -m unittest discover -s tests -p test_repository.py -v
```

Ожидается 15 S6.2 PASS, 22 S6.1 PASS (в S6.1 проверка FIFO пропускается
на Windows, если она не поддерживается). Старые AI-тесты не запускайте для этой
проверки: они могут долго ожидать модель, а S6.2 модель вообще не использует.

## Пробный снимок Python-примера

Команды ниже используют **новую отдельную тестовую БД** во временной папке,
а не текущую `.securitylab`. Папка с исходным проектом остаётся без изменений.

```powershell
$state = Join-Path $env:TEMP 'SecurityLab_S62_DemoState'
$project = py -3 -m securitylab --state "$state" repo add ".\examples\s6_repos\python_api" --name "Python example" | ConvertFrom-Json
$snapshot = py -3 -m securitylab --state "$state" repo snapshot $project.id | ConvertFrom-Json
py -3 -m securitylab --state "$state" repo verify-snapshot $snapshot.snapshot_id
py -3 -m securitylab --state "$state" repo plan $snapshot.snapshot_id
```

В первой проверке будет `VERIFIED_CONTENT_HASHES`, в плане —
`NON_EXECUTING_PROFILE_PLAN` и `execution_permission: DENIED`. Это верно:
исполнение проекта пока выключено до подтверждения контейнерной границы доверия.

Если нужно получить список снимков:

```powershell
py -3 -m securitylab --state "$state" repo snapshots $project.id
```

Если папки примеров нет, можно создать тестовый каталог со своим
`pyproject.toml` или добавить **другую локальную копию**, не оригинальный проект.
Не указывайте production-каталоги с секретами. Копии могут включать файлы,
содержимое которых не распознано по имени как секретное.

**Ограничения:** 8 МиБ на файл, 128 МиБ на снимок, максимум 10 000 файлов.
Хеши не защищают от одновременного злонамеренного изменения источника и не
заменяют Git-коммит. `scan` по-прежнему сообщает BLOCKED.

## Полное восстановление исходников

Архив содержит `SecurityLab_S6_2.bundle` со всей историей. Чтобы восстановить
проект в **другой пустой папке**, можно выполнить:

```powershell
git clone ".\SecurityLab_S6_2.bundle" ".\SecurityLab_Source"
git -C ".\SecurityLab_Source" rev-parse --short HEAD
```

Не выполняйте `git clone` поверх уже установленного рабочего каталога.
