# S8.1 validation and interaction coverage

Date: 2026-11-13. Backend base: 73aeddb (S7.4).
UI source: user-provided revised securitylab-ui, Drive folder 1YaGICLlOPyDlMZ1ZOlIAraxIp-4Ald3o.
No visual redesign. Added truthful status/model bindings, same-origin core bootstrap and capability limits.

## Automated checks

- 9 new Python dashboard tests passed: real local HTTP, Host/CSRF refusal, static bootstrap,
  profiles/schema, immutable selected config through worker, changed-config rejection,
  project/snapshot bindings, historical DTO, restart interruption, no fake cancel.
- 51 existing access tests passed (mock model/Docker observer, real isolated Git in workflow tests).
- 37 existing AI/config/limit tests passed.
- DTO integration script passed: PASS/FIXED/security_verdict, BLOCKED/null,
  shaped DTO preservation, NEEDS_REVIEW, STOPPED, unknown verdict.
- TypeScript and Vite production build passed. Local fonts and SVG assets included.
- Real model inference, Windows Docker, GPU allocation: not tested in this environment.
- Playwright browser could not launch: Chromium socket EPERM. No visual/mobile/click-pass claim.

## Interaction matrix

| Feature | Trigger | Expected / persisted | Baseline | After |
|---|---|---|---|---|
| Projects/snapshots | Open / register / snapshot | Existing core registry | Simulator | API connected; fixture read test passed; browser untested |
| Model choice | Settings / new run select | Browser selection; immutable server job config | Simulator profile ID | Worker pin test passed; click/reload untested |
| Launch | Valid form + preflight + start | Core access-ai, job and summary | Simulated | Worker path implemented; actual model run untested |
| Read run | Poll / open history | Core execution/verdict/finding | PASS and fields mis-mapped | DTO/API tests passed |
| Export | Patch / artifact | Text only; bounded run allowlist | Mock content | Core files connected; actual browser download untested |
| Cancel (high risk) | Cancel active access-ai | Must clean up and persist stop | Simulator cancellation | Unsupported; button disabled; API refusal test passed |
| Theme/navigation/filter | Existing UI controls | Original layouts and behavior | Existing source | Preserved source; browser regression blocked |
| Restart | Restart Python API | Do not auto-retry interrupted job | No core jobs | Persistence test passed |

Three primary operator tasks: select project/snapshot; select model and launch;
inspect result/evidence/patch. Critical action: actual execution starts only after
server-side validation; UI never reports a simulated pass for a core run.

## Deliberate scope limits

Read history: access_ai only. No universal scanner, multi-module patch engine, job queue,
model downloader, safe cancellation, telemetry or GUI profile editor. Existing CLI remains.
Old summaries lack start timestamps; file timestamp is explicitly identified, duration unavailable.
Check table reports HTTP observations; complete policy/body checks stay in stage reports.
