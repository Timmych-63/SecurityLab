# Результаты проверки — 2026-11-08

Среда: Linux, Python 3.12.14, Git. Docker/Hermes/Ollama/nvidia-smi не установлены.

Команда: `python3 -m unittest discover -s tests -v`

**37 tests, PASS 37, FAIL 0, skipped 0; 16.103 s**.
Полный вывод: `docs/test-output.txt`.

Покрытие сценариев:
- полный реальный процессный прогон синтетического дефекта до/после known patch;
- отсутствие изменения main, выделенная ветка, diff и обратный коммит;
- реальное аварийное завершение worker с кодом 77 и восстановление;
- прерывания после стадий, повтор уже сделанного Git-коммита;
- stop/retry, лимит попыток, блокировка второго worker другим процессом;
- атомарность переходов, повторное открытие SQLite, восстановление JSONL;
- отказы валидатора при отсутствии доказательств, старой ревизии, изменённом тесте,
  пустом наборе проверок, timeout/cancel/truncation, грязной ветке и изменении main;
- path traversal, Git paths и symlink escape, роли не могут close/execute/merge;
- неизвестный/изменённый исходник не запускается хостовым runner;
- CLI от enqueue до отчёта, закрытый scan, HTML escaping и CSP;
- тайм-аут, отмена, stderr/exit code, ограничение сохраняемого stdout;
- TOML: корректные значения принимаются, неизвестные ключи и bool вместо int отвергаются.

В первом прогоне 32 тестов одна проверка ожидала 8 событий вместо фактических 7
(created + started + 5 transitions). Исправлено ожидание теста; далее добавлены
проверки конфигурации, реальной смерти процесса и отката. Итоговый прогон выше.

Не заявляется: покрытие строк/ветвей в процентах, успешность реального AI,
контейнерной изоляции, Windows, GPU, или внешних проектов.
Шаблоны Compose проверены чтением; `docker compose config/build/run` не выполнены.
Визуальная проверка HTML в браузере не выполнена; проверены генерация и escaping.

## UTF8 hotfix — 2026-11-08

По присланному Windows-выводу: 35 PASS, 1 ERROR, 1 SKIP из 37.
ERROR: тест отчёта использовал Path.read_text() без encoding; Windows выбрал CP1251.
Сам отчёт сохранялся корректно как UTF-8. Исправлено явное encoding='utf-8'.
Аналогичные чтения/записи тестов и compile-проверка приведены к UTF-8.
Новый регрессионный сценарий содержит кириллицу/emoji и имитирует CP1251 default.
Повторный Linux-прогон: 38 PASS, 0 FAIL, 0 SKIP, 16.625 s.
Полный вывод: docs/test-utf8-output.txt. Windows-повтор после патча ещё NOT TESTED.
Docker: по выводу пользователя клиент/Compose установлены; Linux daemon недоступен.

## S1 — Linux, 2026-11-08

45 tests PASS, 0 FAIL, 0 SKIP, 16.666 s. Полный вывод: test-isolation-output.txt.
7 новых тестов проверяют оценку 16 условий контейнера: корректные/опасные/отсутствующие
наблюдения, тайм-аут вместо доказательства сетевой изоляции, лимиты и mount parsing.
Это unit-тесты логики; реальные 16 проверок на Docker ПК пользователя ещё не выполнены.
Из присланного вывода пользователя: Windows UTF8 fix подтверждён (37 PASS, 1 SKIP),
Docker Linux Engine, сборка образа и demo DONE подтверждены.

## S2 — Linux, 2026-11-08

70 tests PASS, 0 FAIL, 0 SKIP, 20.360 s. Полный вывод: test-s2-output.txt.
25 новых тестов: строгий job-контракт и Unicode, запрещённые поля/пути/дубликаты,
ресурсные аргументы, stdin/EOF/тайм-аут записи, проверка Docker endpoint/image,
обработка exit status, timeout, OOM, ошибок, cleanup и сохранение intent до create.
DockerBroker в этих проверках использует FakeDocker: живой Docker S2 NOT TESTED.
Фактические пять сценариев --self-test требуется выполнить на ПК пользователя.
S1 на ПК пользователя уже подтверждён: 16 PASS, b4f21324bcaf419ea62cece28fecb87c.

## S3 — 2026-11-08

`python3 -m unittest discover -s tests -v`: 90 tests, all PASS, 28.809 s.
Full output: test-s3-output.txt. Docker workflow tests use a mock broker that runs only reviewed fixture constants locally. Live Docker S3: NOT TESTED in this environment. User confirmed S1 (16 PASS) and S2 (5 scenarios, cleanup PASS) on Windows before this update.

## S3 Windows acceptance
User supplied run d6f559e8291348529e92dc44e55fb3f4: DONE/FIXED,
scripted-demo-docker-no-ai, attempts=1, error=null. Accepted for synthetic scope.

## S4 implementation
109 tests PASS (42.112s), full log test-s4-output.txt. AI/Docker transports mocked.
Actual pinned Hermes Python API exercised against fake HTTP model: PASS,
hermes-api-probe-output.txt. No real model inference or Docker in development environment.
Windows S4/live model/build: NOT TESTED pending user output.

## S4.1
113 tests PASS (29.469s), test-s41-output.txt. Live S4.1 pending.
User S4 real Hermes/model smoke PASS; full exercise blocked at Red before execution.
