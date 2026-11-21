# S11.4 — фиксирован краш ядра на гипотезах без ключа action

Итоги прогона №7 (20.11.2026, дашборд) — два разных останова, разбор по файлам:

1. **Краш ядра (исправлен в этом обновлении).** Финальный ответ модели был
   `{"hypotheses": [...]}` без ключа `"action"`. Валидатор `validate_reply` допускает
   эту форму (4 разрешённых набора ключей), а цикл Red читал `proposal['action']`
   напрямую и умирал с `KeyError('action')` — в дашборде это выглядело как
   «Результат: проверка остановлена · Причина: 'action'». Прогон к этому моменту
   успел потратить решения и независимые наблюдения — stages после последнего
   успешного решения в `summary.json` не попали (файлы `decision_NN.json` и
   папки стадий `http_NN` в каталоге прогона сохранились). Исправление: ядро
   трактует допущенную форму как финальные гипотезы и продолжает цикл —
   подтверждение, Blue, baseline и коммит идут как обычно. Добавлен регрессионный
   тест `test_final_hypotheses_without_action_key_complete_the_cycle`; полный
   набор 421/421.

2. **Второй останов («Hypothesis must reference an HTTP observation») исполнял
   СТАРЫЙ код.** Его `summary.json` не содержит ни пометки «Решение N отклонено
   валидатором дважды» в `notes`, ни rejected-маркеров в `ai_calls`, а прогон
   прекратился после первого же отклонённого решения. В S11.3 этот сценарий
   обрабатывается иначе: решение тратится, причина попадает в `notes` и в историю
   модели, недозондированные пары гипотез автопроверяются ядром (red_assist),
   остановка — только после двух отклонений подряд. Вывод: процесс дашборда не был
   перезапущен после установки обновления — Python загружает модули при старте
   процесса, и файлы на диске, обновлённые позже, действующий процесс не видит.

## Что делать

1. Примените обновление (архив включает все правки S11.3 — достаточно одного
   применения даже с чистой S11.2):

```powershell
powershell -ExecutionPolicy Bypass -File .\apply_S11_4.ps1 -ZipPath .\SecurityLab_S11_4_update.zip
```

Скрипт проверит маркеры правок, забэкапит заменяемые файлы в `_backup_S11_4\`,
пересоберёт образ с контролем `CACHED` на шаге `COPY securitylab` и запустит
`ai-smoke`.

2. **Полностью закройте окно дашборда (Ctrl+C) и запустите заново** — иначе
   процесс продолжит жить со старыми модулями в памяти:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Start-SecurityLab.ps1
```

3. Проверка, что на диске новый код (и после перезапуска его исполняет и дашборд):

```powershell
Select-String -Path .\securitylab\research_cycle.py -Pattern "proposal\.get\('action'\)"
Select-String -Path .\securitylab\research_contract.py -Pattern 'SUGGESTED NEXT PROBES'
```

Обе команды должны найти совпадение. В новом прогоне признак живого S11.3+ — блок
`SUGGESTED NEXT PROBES` в промптах (receipts в `.securitylab/ai/<id>/calls/`) и
строка «Корректирующая попытка после автопроверки путей гипотез» при отклонении.

## Проверка поставки

Маркеры после распаковки: `proposal.get('action')` и `Live run #7`
(securitylab/research_cycle.py), `S11.4` (README_S11_4_RU.md), плюс все маркеры
S11.3: `probe_suggestions` и `SUGGESTED NEXT PROBES` (research_contract.py),
`observed_stage` (research_cycle.py), `observedStage` (dashboard_dto.py),
`ollama list` (scripts/Start-SecurityLab.ps1), `unless-stopped` (compose.ai.yaml),
`frequency_penalty` (ai.example.toml), `AuthzNotes` (examples/research/authznotes.md),
`S11.3` (README_S11_3_RU.md).

```powershell
py -3 -m unittest discover -s tests -p "test_research_*.py" -v
py -3 -m unittest tests.test_dashboard tests.test_ai -v
```

## Прогон №8 — что смотреть

- Останов «Причина: 'action'» больше невозможен: финальные гипотезы без ключа
  `action` принимаются ядром, цикл доходит до confirm/baseline/candidate/recheck.
- Отклонённое решение больше не убивает прогон: тратится одно решение, в `notes`
  появляется «Решение N отклонено валидатором дважды», недозондированные пары
  автопроверяются ядром, остановка — только после двух отклонений подряд (и это
  честный сигнал прислать `summary.json` + receipts).
- Скорость: 2b отвечает 1,5–11 минут на решение; при бюджете 3600 с реалистично
  4–8 решений. Если хотите больше решений за прогон — уменьшайте не таймаут,
  а объём ответа (`max_output_tokens`) не нужно; лучше оставить как есть и
  смотреть `coverage` в `summary.json`.
- После прогона пришлите `summary.json`; если прогон остановился досрочно —
  добавьте receipts из `calls\` и последний `decision_NN.json`.

Подробности цикла: `docs/S11_1_RESEARCH_CYCLE_RU.md`; план: `docs/RESEARCH_PLAN_RU.md`;
статус: `docs/STATE.md`.
