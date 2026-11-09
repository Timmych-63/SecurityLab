# S4.2 — one corrective Blue retry

Observed Windows run 5e36c06e6300438dbc0ac4e4ee1929d1: Red admitted;
Blue rejected before any verification run. The proposal omitted RECORDS and
read the owner before the missing-record guard. Red's prose also contradicted its
structured case; its prose is not behavioral evidence.

Changes:
- Blue's initial prompt requires the entire module, original RECORDS and original
  401/404 guards in order. The structured Red case is separated from its untrusted prose.
- One corrective retry only for rejected Blue output (JSON/schema/AST). A fresh
  Hermes agent receives the original task, bounded rejected text and static feedback.
- Static diagnostics identify missing/changed RECORDS and changed initial guards.
  They do not execute the candidate or claim to prove its runtime behavior.
- The reviewed FIXED implementation is never supplied as an answer or inserted as
  an automatic repair. The same strict AST gate must pass, then S3 must pass.
- Both raw responses (AI_RESPONSE_JSON) and numbered decisions/feedback
  (AI_ATTEMPT_JSON) are persisted in the broker call's stderr receipt.
- Unexpected tools and provider failures are not retried. Red and smoke have one attempt.
- The two Blue attempts share the existing 240-second conversation budget and the
  existing 300-second host process timeout. No extra five-minute allowance is added.
  The second attempt may therefore have insufficient time and remain BLOCKED.
- AI-role queue persistence and broad arbitrary-patch admission are still not implemented.

Apply over S4.1 in the project folder, then:

```powershell
docker compose -f compose.ai.yaml --profile build build hermes
py -3 -m securitylab ai-demo
```

Run the second command after the build succeeds. Do not pull the model again or
repeat S1/S2/S3/ai-smoke. The model service should still be running. If it was stopped:
`docker compose -f compose.ai.yaml up -d model`.
Send the final JSON. A remaining rejection does not justify weakening the validator.

Tests include the observed bad Blue source: rejection → feedback → valid proposal,
two rejections → stop, valid first response → no retry, malformed JSON correction,
forbidden tools → immediate stop, exhausted shared budget → no second call.
These use scripted responses. Live model improvement remains NOT TESTED.
