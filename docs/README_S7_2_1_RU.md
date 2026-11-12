# SecurityLab S7.2.1 — корректировка Blue по независимому результату

Основа: S7.2, commit 8d389d6. Обновление не расширяет профиль допуска приложения и не отключает проверки.

## Изменения

Если фактический код Blue снова воспроизводит утечку чужой записи, система проверяет целостность доказательств и даёт Blue одну последнюю попытку. В запрос передаются предыдущий кандидат и структурированные HTTP expected/actual по неизменной внешней политике. Готовое исправление не подставляется.

Всего разрешено два вызова Blue: ошибка JSON уже расходует этот бюджет. Если первая принятая схема получена на второй попытке, новой функциональной попытки нет. Каждый вызов модели ограничен 300 секундами; Red и максимум два Blue дают до 15 минут только ожидания модели, плюс Docker/Git. Это верхняя граница тайм-аутов модели, не гарантированная длительность запуска.

Повтор допускается только при ACCESS_POLICY_VIOLATION_REPRODUCED с корректными контролями. Неясное поведение или повреждённые контрольные ответы остаются NEEDS_REVIEW. Ошибка инфраструктуры, тайм-аут, cleanup FAIL, подмена snapshot/политики/receipts или смена образов дают BLOCKED. Новый кандидат должен пройти независимую проверку и recheck. FIXED относится исключительно к проверенной политике. Автоматического merge/push нет.

Файлы candidate_1.py и candidate_2.py сохраняются отдельно; candidate.py содержит последний вариант. Стадии: baseline, candidate, при необходимости candidate_retry, recheck. В summary добавлены candidates, blue_attempts_used. ai_receipt_sha256 теперь индексируется ID квитанции, чтобы сохранять все принятые предложения. Код исходного проекта не изменяется.

## Установка

Распакуйте ZIP во временную папку. Скопируйте папки securitylab, tests и docs поверх одноимённых папок текущей S7.2 с заменой файлов. Не удаляйте состояние или Docker volumes. Полный Git bundle внутри архива нужен для восстановления/переноса, для обычного обновления его не импортируйте.

В PowerShell из корня SecurityLab:

```powershell
py -3 -m unittest discover -s tests -p test_access_ai.py -v
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
docker build -f docker/Hermes.Dockerfile -t securitylab-hermes:s4 .
if ($LASTEXITCODE -ne 0) { throw 'Hermes build failed' }
docker compose -f compose.ai.yaml up -d model
if ($LASTEXITCODE -ne 0) { throw 'Model start failed' }
docker compose -f compose.ai.yaml exec -T model ollama list
```

Ожидается 26 тестов OK. Модель повторно скачивать не нужно. Если сервер ещё не готов, дождитесь успешного ollama list. FastAPI/demo образы в этом обновлении не изменены.

Использование существующего snapshot из последнего запуска:

```powershell
$state = Join-Path $env:TEMP 'SecurityLab_S72_DemoState'
$policy = '.\examples\security_policies\record_ownership.json'
py -3 -m securitylab --state "$state" repo access-ai 2ceb1b1ab21245d8ac979316cf434ed6 --entry app/main.py --policy "$policy" --execute
```

Если временный snapshot удалён, создайте новый по docs/README_S7_2_RU.md, затем используйте полученный snapshot_id. Не ослабляйте проверку снимка.

## Приёмка

Локально прошли 174 теста: access_ai (26), access_baseline, ai, blue_prompt, repository, snapshots, probe, http_probe, fastapi_probe, package_probe. Полный набор остальных исторических тестов в этой поставке не запускался.

Локальные тесты используют mock Hermes/Docker и настоящий изолированный Git; это не проверка реального inference. На машине разработки Docker отсутствует. Реальный прогон Windows/Hermes после установки обязателен и пока не выполнен. Неверный повторный ответ модели допустимо завершает NEEDS_REVIEW — это не повод подменять его шаблоном.

Отправьте итоговый JSON нового запуска; при отказе нужны его error и соответствующая квитанция. Не повторяйте старую диагностику DNS или уже исследованный cosmetic-only кандидат S7.2.
