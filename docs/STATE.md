# АКТУАЛЬНАЯ ТОЧКА — S6.1, 2026-11-09

- Source baseline: S5.1, Git `6bf3f56` (полный fixture AI pipeline подтверждён
  пользователем на Windows, AI run `f31d8098dbb5439db650a7f97e0328bb`,
  `PASS/FIXED`; не переносить этот статус на другие приложения).
- S6.1: реализованы `repo inspect/add/list/show` и профили определения стека,
  защищённая от простого обхода каталогов инвентаризация, регистрация в SQLite.
  Проекты не выполняются; `scan` по-прежнему BLOCKED. См. `docs/S6_1.md`.
- S6.1 прошёл отдельные unit/негативные тесты в окружении разработчика.
  Windows-приёмка S6.1 пока не проводилась. Полный legacy-suite здесь
  завис на интеграционных тестах; его PASS не заявлен.
- **Следом S6.2**: hash-verified source snapshot + профили запуска и новая
  trust boundary для тестирования разных проектов; потом общий Red/Blue,
  независимая проверка, Git integration и Dashboard.
- Все записи ниже — исторические этапы, а не текущие инструкции запуска.

---

# SecurityLab — S4 implementation, 2026-11-08

## Accepted on user's Windows PC
- Core UTF8 fix: 37 PASS + 1 expected Windows symlink SKIP.
- S1 isolation configuration: 16 PASS.
- S2 broker: normal/nonzero/timeout/output_limit/boundaries and all cleanup PASS.
- S3 full Docker fixture cycle: DONE/FIXED, one attempt, no error;
  run d6f559e8291348529e92dc44e55fb3f4. Do not repeat S1/S2/S3 without new cause.

## Current S4
Hermes adapter, isolated worker, sequential Red/Blue proposals, strict schemas,
AST-equivalent-to-reviewed-fix gate, child S3 validation, persisted AI summaries.
New ai-smoke / ai-demo and scripts/Start-S4.ps1. See S4_HERMES.md for exact boundary.
109 automated tests PASS; real pinned Hermes + fake HTTP model API probe PASS.
Live Docker image build, Ollama model generation, Windows S4: NOT TESTED.
Source base: 782916138b34f1e7893b7495ec7e067d3e5d16cb. Final commit in S4_MANIFEST.json.

## Next action
User overlays S4 archive and runs Start-S4.ps1. Obtain ai-smoke PASS and ai-demo
PASS/FIXED or diagnose first error. Do not claim live AI success from mocked tests.
Model Qwen3.5 2B, CPU initially, context64K, one model/two sequential roles.
Hermes pinned source e075441241b8d626789b4aae0e376f86eabf824d. No CS AIReviewer.

## Product plan and limitations
First constrained AI exercise → independent arbitrary-patch behavior checks on an
approved real project → Dashboard → multi-service support and stabilization.
Dashboard is the main UI; minimal CLI and HTML/JSON reports remain.
No arbitrary-project scan, cloud fallback, automatic merge or model-declared FIXED.
No hard-kill orphan reaper or resumable AI queue yet. Current AI workflow canonicalizes
only the reviewed AST; it is not a general autonomous security audit.

## S4.1 current checkpoint
User real ai-smoke PASS: a71a05e55388407788b15700a93cdd09.
S4 build/model/inference accepted; full AI cycle BLOCKED at Red in run
7b4972e37f7748908c658468e994babf. Original rejected response was not retained.
S4.1 replaces the two-pair whitelist and logs rejected replies. See S4_1_RED_FIX.md.
Next: cached Hermes rebuild then ai-demo only. Full cycle remains pending.

## S4.2 current checkpoint
User S4.1 run 5e36c06e6300438dbc0ac4e4ee1929d1 reached Blue. Invalid Blue
proposal blocked before execution (missing RECORDS, owner read before 404 guard).
S4.2 adds one bounded corrective retry, preserving strict AST/S3 checks and both replies.
Same total role timeouts. Next: cached Hermes rebuild and ai-demo; no model download.
Live full AI cycle still pending. See S4_2_BLUE_RETRY.md.

## S4.3 current checkpoint
User e81dfed72e514e2f9ab8f72c30b27ce4 timed out in Blue after 300.0245s, cleanup PASS.
S4.3 replaces shared-budget retries with separate containers and 300s per attempt.
Added system JSON contract, JSON response_format, explicit timeout status/progress.
119 automated tests and real-Hermes/fake-HTTP format probe PASS; live S4.3 pending.
Next: cached Hermes rebuild, ensure model running, ai-demo. See S4_3_ATTEMPTS.md.
