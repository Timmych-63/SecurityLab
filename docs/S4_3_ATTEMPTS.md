# S4.3 — independent Blue attempts and JSON response mode

## Observed cause
User run e81dfed72e514e2f9ab8f72c30b27ce4: first Blue reply rejected;
host timeout at 300.0245 seconds, timed_out=true, truncated=false, OOMKilled=false.
Container state was sampled before cleanup; cleanup PASS. No code verification ran.
The previous S4.2 shared role budget prevented a full corrective attempt.

Pinned Hermes agent/prompt_builder.py DEFAULT_AGENT_IDENTITY asks for a report of
what changed, what was verified and what is left. This is a plausible influence on
verified/left keys, not proof of the model's internal reason for choosing them.

## Changes
- One Hermes conversation per disposable container.
- Host broker performs at most two Blue attempts, each with its own 300-second
  process limit and 240-second Hermes conversation budget. Red has one attempt.
- A second attempt is permitted only after a completed worker rejection with a
  bounded captured reply and verified successful cleanup. It receives the prior
  reply as untrusted data and static feedback. No automatic retry on timeout,
  OOM, truncated output, provider failure, unexpected tools or cleanup failure.
- Each attempt has a separate host receipt, ID, request hash and attempt number.
- Explicit TIMEOUT/CANCELLED/OUTPUT_LIMIT/RESOURCE_LIMIT in receipt and error text.
- Console prints role, attempt number and limit before each attempt (stderr),
  keeping final stdout JSON usable. Successful summary includes blue_attempts.
- Dedicated system instruction specifies the exact response keys and forbids
  Markdown/report sections. response_format=json_object requests JSON generation
  from Ollama. Local schema, AST gate and S3 proof checks remain mandatory.
- No schema fallback silently disables JSON mode if the provider rejects it.

The source/task limits remain unchanged. No arbitrary Python execution, no
automatic candidate repair and no model-declared FIXED. S4 remains constrained
to the reviewed fixture AST. A more general independent behavior validator is
still a later development step.

## Windows update
Overlay archive on S4.2, then:

```powershell
docker compose -f compose.ai.yaml --profile build build hermes
docker compose -f compose.ai.yaml up -d model
```

After successful build/start and once the server responds to `ollama list`:

```powershell
py -3 -m securitylab ai-demo
```

No model download is needed. If model was already running, do not repeat readiness
checks. Up to 5 minutes Red + 5 minutes Blue1 + 5 minutes Blue2, plus bounded
container lifecycle and S3 checks. These are limits, not measured typical latency.
The second Blue call is made only when the first completed with rejected content.

## Validation
119 automated tests PASS (31.300s), test-s43-output.txt. Six retry tests replaced
S4.2's shared-budget expectations with separate-container/budget/receipt tests,
including cleanup-before-retry and timeout-without-retry.
Real pinned Hermes API probe with a fake HTTP model: PASS. It verifies the actual
outgoing response_format and system instruction, not just constructor arguments.
See s43-hermes-probe.txt. Real model behavior and Windows S4.3 remain NOT TESTED.

Provider format reference: https://docs.ollama.com/api/openai-compatibility
