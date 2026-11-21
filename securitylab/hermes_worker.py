"""One proposal per disposable Hermes process. No project/state mounts or tools."""
import contextlib
import json
import os
from pathlib import Path
import sys
from urllib.request import urlopen
from .ai_contract import HERMES_REVISION, MODEL, MODEL_DIGEST, strict_json, digest
from .proposal_modes import proposal_prompt, proposal_validate, proposal_feedback, proposal_system
from .policy import PolicyError
from .ai_config import AIConfig, from_dict
from .research_contract import (TASK_BLUE, TASK_RED, blue_corrective_instruction,
                                corrective_instruction)


def corrective_feedback(reason):
    """Compact model-facing instruction for one corrective attempt."""
    return ('Your previous response was rejected: ' + reason +
            '. Reply again with exactly one compact valid JSON object exactly as '
            'prescribed by the schema; do not repeat the rejected text and add no prose.')


def transport_rejection(detail):
    """Classify a Hermes-level conversation failure as a recoverable rejection.

    Truncated output (finish_reason='length'), degenerate repetition and empty
    responses are weak-model failures, not contract violations: they are reported
    as a REJECTED attempt with corrective feedback instead of ending the run.
    """
    lowered = detail.lower()
    if ('truncat' in lowered or "finish_reason" in lowered
            or 'max output' in lowered or "'length'" in lowered):
        reason = 'response truncated: model hit the output token limit'
    elif 'repeat' in lowered or 'degenerat' in lowered or 'loop' in lowered:
        reason = 'response degenerated into repeated text'
    else:
        reason = 'model returned no usable answer'
    return reason, corrective_feedback(reason)


def sampling_overrides(config):
    """Deterministic JSON mode plus optional repetition suppression knobs."""
    overrides = {'temperature': 0, 'response_format': {'type': 'json_object'}}
    if config.frequency_penalty is not None:
        overrides['frequency_penalty'] = float(config.frequency_penalty)
    if config.presence_penalty is not None:
        overrides['presence_penalty'] = float(config.presence_penalty)
    return overrides


def invoke(req, agent_class, capture=None, config=None):
    config = config or AIConfig()
    query = proposal_prompt(req)
    attempt = 2 if 'retry' in req else 1
    agent = agent_class(model=config.model, base_url=config.server_url + '/v1', api_key='local-only',
                        provider='custom', api_mode='chat_completions', enabled_toolsets=[],
                        quiet_mode=True, skip_context_files=True, skip_memory=True,
                        skip_background_review=True, load_soul_identity=False,
                        save_trajectories=False, max_iterations=2, max_tokens=config.max_output_tokens,
                        run_budget_seconds=config.timeout_seconds - 60, fallback_model=None,
                        reasoning_config={'enabled': False},
                        request_overrides=sampling_overrides(config))
    if agent.tools:
        raise PolicyError('Hermes unexpectedly enabled tools')
    def deny(*args, **kwargs):
        raise PolicyError('Tool execution forbidden in proposal mode')
    agent._execute_tool_calls = deny
    result = agent.run_conversation(user_message=query, system_message=proposal_system(req))
    detail = None
    if not isinstance(result, dict):
        detail = 'Hermes returned no conversation result'
    elif result.get('error'):
        detail = str(result['error'])
    elif (not isinstance(result.get('final_response'), str)
          or not result['final_response'].strip()):
        detail = 'Hermes returned an empty response'
    if detail is not None:
        reason, feedback = transport_rejection(detail)
        print('AI_RESPONSE_JSON=' + json.dumps(feedback, ensure_ascii=True), file=sys.stderr)
        print('AI_ATTEMPT_JSON=' + json.dumps({'role': req['role'], 'attempt': attempt,
              'status': 'REJECTED', 'reason': detail[:300], 'feedback': [feedback]}), file=sys.stderr)
        raise PolicyError('Hermes conversation failed: ' + reason + '; ' + detail[:300])
    for message in result.get('messages', []):
        if message.get('role') == 'tool' or message.get('tool_calls'):
            raise PolicyError('Unexpected tool invocation')
    raw_response = result.get('final_response')
    if capture is not None:
        capture(raw_response[:32768] if isinstance(raw_response, str) else None)
    value = None
    try:
        value = strict_json(raw_response)
        if req['role'] == 'smoke':
            if value != {'ready': True} or type(value['ready']) is not bool:
                raise PolicyError('Smoke response invalid')
        else:
            proposal_validate(req, value)
    except PolicyError as exc:
        if req.get('task') in (TASK_RED, TASK_BLUE):
            # Research retries bound corrective feedback at 4000 bytes; the raw
            # response can be far larger and would stop the run with 'Invalid
            # research corrective feedback'. The composed note carries the reason
            # plus the canonical response shapes (live run #5: a weak model kept
            # misforming http checks across the corrective attempt without a
            # worked example). Discovery/review/S7.2 bounds are 16000 bytes and
            # deliberately reuse the raw response instead.
            note = (corrective_instruction(exc, req=req, value=value)
                    if req.get('task') == TASK_RED
                    else blue_corrective_instruction(exc))
            print('AI_RESPONSE_JSON=' + json.dumps(note, ensure_ascii=True), file=sys.stderr)
        # Surface the rejected proposal so the core can auto-probe its own
        # unobserved hypothesis pairs (live run #5: 'Hypothesis must reference
        # an HTTP observation' killed the run even though one probe had run).
        try:
            dumped = json.dumps(value, ensure_ascii=True)
        except (TypeError, ValueError):
            dumped = None
        if dumped is not None and len(dumped) <= 16000:
            print('AI_PROPOSAL_JSON=' + dumped, file=sys.stderr)
        print('AI_ATTEMPT_JSON=' + json.dumps({'role': req['role'], 'attempt': attempt,
              'status': 'REJECTED', 'reason': str(exc),
              'feedback': proposal_feedback(req, value) if req['role'] == 'blue' else [str(exc)]}), file=sys.stderr)
        raise
    print('AI_ATTEMPT_JSON=' + json.dumps({'role': req['role'], 'attempt': attempt,
          'status': 'ADMITTED'}), file=sys.stderr)
    return value


def main():
    try:
        if not Path('/.dockerenv').exists() or os.geteuid() != 10001:
            raise PolicyError('Hermes worker must run in its unprivileged container')
        raw = sys.stdin.buffer.read(32769)
        if len(raw) > 32768:
            raise PolicyError('Request too large')
        req = strict_json(raw.decode('utf-8'))
        proposal_prompt(req)
        config = from_dict(json.loads(os.environ.get('SECURITYLAB_AI_RUNTIME', '{}')))
        # The only runtime model endpoint is on the private Docker network.
        with urlopen(config.server_url + '/api/tags', timeout=10) as response:
            body = response.read(1048577)
        if len(body) > 1048576:
            raise PolicyError('Model inventory too large')
        models = json.loads(body)['models']
        selected = [x for x in models if x.get('name') == config.model]
        if len(selected) != 1 or selected[0].get('digest') != config.model_digest:
            raise PolicyError('Expected model missing or digest changed; preload the pinned model')
        home = Path(os.environ['HERMES_HOME'])
        home.mkdir(parents=True, exist_ok=True)
        (home / 'config.yaml').write_text(f'model:\n  context_length: {config.context_tokens}\n  ollama_num_ctx: {config.context_tokens}\n', encoding='utf-8')
        with contextlib.redirect_stdout(sys.stderr):
            sys.path.insert(0, '/opt/hermes')
            from run_agent import AIAgent
            value = invoke(req, AIAgent, config=config, capture=lambda raw: print(
                'AI_RESPONSE_JSON=' + json.dumps(raw, ensure_ascii=True), file=sys.stderr))
        print(json.dumps({'schema_version': 1, 'role': req['role'], 'request_sha256': digest(req),
                          'hermes_revision': HERMES_REVISION, 'model': config.model,
                          'model_digest': selected[0]['digest'], 'tools': [], 'proposal': value}))
        return 0
    except Exception as exc:
        print(f'BLOCKED: {type(exc).__name__}: {str(exc)[:1500]}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
