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
