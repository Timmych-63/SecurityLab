# S4.1 — Red admission and rejected-response diagnostics

User Windows acceptance: ai-smoke PASS, run a71a05e55388407788b15700a93cdd09,
Qwen3.5 2B digest 0689d44085e06d165161a8a9a1731344278cfb5aade63a3c3dbdb48ab54b130a.
Hermes Docker build, local model loading and actual inference are now confirmed.
The ai-demo run 7b4972e37f7748908c658468e994babf was BLOCKED during Red,
before Blue or S3 execution. The old worker discarded rejected final responses,
so the original candidate and exact cause cannot be reconstructed from that output.

Changes:
- Replaced two-pair whitelist with checks against the trusted fixture's RECORDS:
  an existing record and a nonempty string caller other than its owner. Unknown
  callers such as mallory are valid in this fixture, consistent with its protected suite.
- Owner reads, null callers, nonexistent records and wrong field types remain denied.
- Prompt explicitly requests literal argument values, not schema placeholders.
- Worker logs bounded escaped AI_RESPONSE_JSON before JSON/schema/semantic validation.
  Broker's host call receipt retains this even when validation fails.
- Error includes rejected user/record_id values for direct diagnosis.
- Blue AST guard and independent S3 acceptance remain required.

Apply archive over S4, then only:

```powershell
docker compose -f compose.ai.yaml --profile build build hermes
py -3 -m securitylab ai-demo
```

Run second command after successful build. Existing model server should still be
running; if it was stopped: docker compose -f compose.ai.yaml up -d model.
No model pull or repeat of ai-smoke/S1/S2/S3 is needed. Cached build layers should
reuse the installed Hermes dependencies; the changed application layer is rebuilt.

If ai-demo is still BLOCKED, send the JSON. For the exact raw answer, take the ID
from its record path and run:

```powershell
Get-ChildItem ".\.securitylab\ai\<ID>\calls\*.json" | ForEach-Object { Get-Content -Raw -Encoding UTF8 $_.FullName }
```

No live S4.1 claim before the user's new output. This repairs known admission and
observability defects; it does not prove the previous model answer was correct.
