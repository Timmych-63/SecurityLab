# Интеграции: исследование и следующий этап

Проверено по официальным источникам 2026-11-08. Здесь нет утверждения о локальном запуске Hermes.

## Hermes

Документация описывает Python-интерфейс `run_agent.AIAgent`, `run_conversation()` и
`final_response`. Указаны `enabled_toolsets`, `max_iterations`, `base_url`,
`skip_context_files`, `skip_memory`, `quiet_mode`. Для каждого задания нужен новый экземпляр.
Текущий официальный способ подготовки исходного окружения — clone и `activate`/PM;
не добавляем неподтверждённый PyPI-пакет `hermes` в зависимости.

Источники:
- https://hermes-agent.nousresearch.com/docs/getting-started/installation
- https://hermes-agent.nousresearch.com/docs/user-guide/local-models
- https://hermes-agent.nousresearch.com/docs/guides/python-library
- https://hermes-agent.nousresearch.com/docs/reference/toolsets-reference

Следующие обязательные действия:
1. В изолированном окружении получить Hermes, зафиксировать release/commit и зависимости.
2. Проверить смысл пустого tool allowlist фактически. Не считать его запретом инструментов по предположению.
3. Подтвердить отсутствие неразрешённых filesystem/network/terminal/MCP/plugin вызовов.
4. Подключить локальный endpoint, выполнить реальный запрос, сохранить версию и ответ.
5. В адаптере выдавать только структурированные предложения. Защиту обеспечит broker вне агента.
6. Не смешивать контексты Red и Blue; ограничить итерации, контекст, генерацию и wall-time.
7. Прогнать весь учебный цикл с реальной моделью. До этого M3 BLOCKED.

## Подготовленные контейнеры

Docker отсутствует в среде разработки. Ни одна команда ниже здесь не запускалась.

Учебный CPU-режим (после установки Docker):

```powershell
docker compose config
docker compose build
docker compose run --rm demo
```

Остановка: `docker compose stop`. Контейнеры без удаления данных: `docker compose down`.
Не применять `down -v` к состояниям, которые нужно сохранить.
Отчёт из тома можно экспортировать после прогона отдельной командой с копированием;
автоматическая Windows-команда экспорта ещё не проверена. Для первого знакомства проще CLI без Docker.

В `compose.yaml` конечное demo-задание без сети, без опубликованных портов,
read-only rootfs, без capabilities, непривилегированный UID, временный /tmp,
лимиты памяти/CPU/PID. Docker socket не монтируется.

`compose.model.yaml` — отдельная заготовка Ollama. Укажите проверенный образ в `.env`,
заранее подготовьте том модели, затем `docker compose -f compose.model.yaml up -d`.
Без предварительной загрузки весов runtime может быть здоров, но генерация недоступна.
Healthcheck `ollama list` проверяет процесс, а не качество/доступность модели.
Runtime пока не связан с оркестратором. CPU — без GPU override;
GPU: `docker compose -f compose.model.yaml -f compose.gpu.yaml up -d`.
Ни наличие CUDA, ни доступность GPU, ни сетевые ограничения фактически не проверены.
Образы и apt-пакеты ещё не закреплены digest/версиями: воспроизводимость Docker-сборки впереди.

Официальные источники конфигураций:
- https://docs.docker.com/compose/how-tos/networking/
- https://docs.docker.com/reference/compose-file/networks/
- https://docs.docker.com/compose/how-tos/gpu-support/
- https://github.com/ollama/ollama/blob/main/docs/faq.mdx

## Проверка на ПК

Сначала выполнить команды README без Docker. Сохранить вывод `doctor`, тестов и `demo`.
После обновления Windows проверить Docker Desktop/WSL2, затем сборку demo-контейнера.
После этого нужна проверка сетевого запрета, ресурсных ограничений, прав томов и остановки.
Только затем — Hermes и модель, выбранная по фактическому замеру RAM/VRAM и скорости.
Не требуются производственные секреты или доступ к настоящим данным.
