# S7.3 — регрессионные проверки доступа

Обновление поверх S7.2.1. S7.2.1 подтверждён реальным Windows-запуском c6764da52c7a4f86ad2bcd21e73233b0: первый кандидат отклонён, второй и recheck прошли, PASS/FIXED, отдельный коммит 80221d4b65c1b20ab28e21988a41a42600eec53b, исходный проект не изменён.

## Что добавлено

Внешняя политика schema_version=2 поддерживает kind=regression для ответов HTTP 401/404 с обязательным эталонным SHA-256 тела. actor=null означает отсутствие X-Test-User, а не строку «None» или пустой заголовок. Доверенный HTTP-проверяющий сохраняет actor=null и доказательства тела. Политики v1 совместимы; старый record_ownership.json не изменён. Всего по-прежнему максимум восемь случаев. Red может выбирать только deny, а не regression.

Новая политика examples/security_policies/record_ownership_extended.json:

| Случай | Ожидается |
|---|---|
| Alice читает one | 200 + прежний хеш данных |
| Bob читает two | 200 + прежний хеш данных |
| Alice читает two | 403 |
| Bob читает one | 403 |
| Без пользователя читают one | 401 + хеш стандартного Unauthorized |
| Без пользователя читают missing | 401 + хеш стандартного Unauthorized |
| Alice читает missing | 404 + хеш стандартного Not Found |
| Charlie читает one | 403 |

Эталонные тела заданы операторской политикой, не извлекаются автоматически из ответа приложения. Это намеренно точный контракт данного примера. Для приложения с другим форматом ошибок нужна собственная политика, а не ослабление сравнения. Проверки не доказывают безопасность вне перечисленных случаев.

Нарушение regression на baseline завершает NEEDS_REVIEW до Blue. Нарушение regression на кандидате завершает NEEDS_REVIEW без повторного вызова Blue и без подтверждённого коммита. Корректирующая попытка S7.2.1 остаётся только для воспроизведённой утечки при целых контрольных сценариях. Это ограничение текущего профиля; исправление произвольных регрессий моделью пока не добавлено.

## Установка и приёмка Windows

Скопируйте securitylab, tests, examples, docs из ZIP в корень существующего проекта, с заменой совпадающих файлов. Не удаляйте state, snapshot или модель. Полный bundle для восстановления лежит в ZIP отдельно; для overlay его не импортируют.

Запустите команды из корня SecurityLab по порядку:

```powershell
py -3 -m unittest discover -s tests -p 'test_access*.py' -v
if ($LASTEXITCODE -ne 0) { throw 'Access tests failed' }

docker build -f docker/Hermes.Dockerfile -t securitylab-hermes:s4 .
if ($LASTEXITCODE -ne 0) { throw 'Hermes build failed' }
docker compose -f compose.ai.yaml up -d model
if ($LASTEXITCODE -ne 0) { throw 'Model start failed' }
docker compose -f compose.ai.yaml exec -T model ollama list
```

Тестов 51 (26 access_ai + 17 access_baseline + 8 access_regression), ожидается OK. На Windows тест symlink может быть пропущен при отсутствии разрешений. Дождитесь успешного ollama list. Перекачивать модель не требуется. Код приложения и runtime-зависимости FastAPI не изменились; доверенный HTTP script передаётся брокером с хоста, demo/FastAPI образы пересобирать не требуется. Hermes пересобирается для нового контракта подсказок.

```powershell
$state = Join-Path $env:TEMP 'SecurityLab_S72_DemoState'
$policy = '.\examples\security_policies\record_ownership_extended.json'
py -3 -m securitylab --state "$state" repo access-ai 2ceb1b1ab21245d8ac979316cf434ed6 --entry app/main.py --policy "$policy" --execute
```

Переменные задавайте ДО запуска команды. Если snapshot исчез после очистки TEMP, создайте новый по docs/README_S7_2_RU.md, не отключайте его проверку. Итог должен показывать checks_total=8. При правильном кандидате: PASS/FIXED, candidate (или candidate_retry) и recheck содержат восемь успешных observations, cleanup PASS, git.verified_commit. При ошибке пришлите полный JSON; NEEDS_REVIEW не заменяется вручную на PASS.

Локально прошли 182 теста в 11 затронутых/связанных наборах; из них 51 тест access*. Полный исторический набор тестов не запускался.

Новый реальный S7.3 Windows/Hermes прогон пока не выполнен. Локальная проверка — имитация AI/Docker, настоящий Git и локальный HTTP-тест доверенного наблюдателя. Это не повторный аудит контейнерной изоляции и не проверка всего приложения.
