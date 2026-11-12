# S7.4 — сменяемая AI-конфигурация и задание на дашборд

Накладывается на S7.3.1. Архив — обновление, не полная установка. Полная история исходников приложена в git bundle. Существующие state, модели, compose.ai.gpu.yaml не заменяются.

## Установка
Распаковать файлы поверх корня проекта. Затем по одной команде в PowerShell:

```powershell
py -3 -m unittest discover -s tests -p 'test_ai*.py' -v
```
```powershell
py -3 -m unittest discover -s tests -p 'test_access*.py' -v
```
Создать личный файл (если его ещё нет):
```powershell
if (!(Test-Path .\ai.local.toml)) { Copy-Item .\ai.example.toml .\ai.local.toml }
```
Выбрать явно для текущего окна PowerShell:
```powershell
$env:SECURITYLAB_AI_CONFIG = (Resolve-Path .\ai.local.toml).Path
```
Проверить структуру без Docker/AI:
```powershell
py -3 -m securitylab.ai_config
```
VALID означает только валидную конфигурацию, не успешное соединение.
Перед следующим AI-запуском пересобрать worker:
```powershell
docker build -f docker/Hermes.Dockerfile -t securitylab-hermes:s4 .
```
Сохранить GPU override при старте сервера:
```powershell
docker compose -f compose.ai.yaml -f compose.ai.gpu.yaml up -d model
```
Обычные ai-demo и repo access-ai автоматически используют выбранный файл. Без переменной среды действуют прежние defaults. Переменную нужно выбрать заново в новом окне; автоматического поиска внутри тестируемого репозитория нет. Ошибка явно указанного файла блокирует запуск, а не возвращает defaults.

## Параметры [ai]
- model и model_digest: менять вместе. Digest — полный SHA256 из /api/tags, не короткий ID из ollama list. Перед загрузкой кандидата worker проверяет выбранную модель в inventory, host проверяет её имя/digest в ответе.
- server_url: http://имя-контейнера:порт без /v1. Сервер должен предоставлять /api/tags и /v1 в указанной приватной internal bridge сети Docker. По умолчанию http://model:11434. Адрес относится к сети контейнера, localhost Windows здесь не подходит.
- network: существующая приватная internal bridge сеть; по умолчанию securitylab-ai-private. Создание сети не выполняется автоматически.
- context_tokens: 64000..131072; нижняя граница текущего pinned Hermes. Это настройка worker, она не меняет Compose-сервер автоматически. Согласуйте OLLAMA_CONTEXT_LENGTH в Compose. Меньшее окно сервера может отклонить сам Hermes.
- max_output_tokens: 256..4096, default2048.
- timeout_seconds: 120..1200, default1200 на каждый AI-вызов; внутренний бюджет на60сек меньше. Лимиты исполнения проверяемого приложения не изменены.

Конфигурация фиксируется один раз на adapter/run и записывается с SHA256 в receipts. Model/server/image availability проверяется при запуске, не командой VALID. Сохранённый профиль не гарантирует поддержку конкретной модели, JSON-format или успешность исправлений. Подмены модели между ролями не допускаются.

## Смена модели и машины
Предварительно загрузите выбранную модель в тот же сервер Ollama и получите её полный digest. Измените только model/model_digest; запустите проверку конфигурации и smoke (py -3 -m securitylab ai-smoke). Для новых endpoint используйте Docker alias и тот же private network. Внешний HTTPS/API-key, удалённый компьютер, произвольный OpenAI-compatible endpoint без /api/tags этим этапом НЕ поддерживаются.
На новом ПК перенесите проект и нужные state отдельно, установите Docker/Python, загрузите модель, настройте GPU для новой машины и повторите независимые проверки. ai.local.toml не переносит модель, Docker-volume или state автоматически.

## Состояние разработки
S7.3 расширенная политика: исходное нарушение и неудачные кандидаты проверяются; успешный полный реальный AI-прогон на8случаях ещё не подтверждён. Последний run67dc5a9cb34d4a0493d63888bcdea075 BLOCKED: первая попытка сохранила нарушение; вторая исчерпала выходные токены и зациклилась. Более долгий timeout это не устраняет.
S7.4 проверен локальными unit/regression тестами с подставными Docker/AI. Реальный контейнерный прогон новых настроек на этом хосте не выполнен.
Следующий этап S8: дашборд по docs/DASHBOARD_PROMPT_RU.md. Затем управление заданиями, расширение профилей, приёмка на новом железе. Дашборд в этом архиве ещё не реализован.
