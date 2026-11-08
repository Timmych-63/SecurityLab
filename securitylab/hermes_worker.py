"""One proposal per disposable Hermes process. No project/state mounts or tools."""
import contextlib
import json
import os
from pathlib import Path
import sys
from urllib.request import urlopen
from .ai_contract import HERMES_REVISION, MODEL, MODEL_DIGEST, prompt, strict_json, validate_proposal, digest
from .policy import PolicyError


def invoke(req, agent_class):
    query = prompt(req)
    agent = agent_class(model=MODEL, base_url='http://model:11434/v1', api_key='local-only',
                        provider='custom', api_mode='chat_completions', enabled_toolsets=[],
                        quiet_mode=True, skip_context_files=True, skip_memory=True,
                        skip_background_review=True, load_soul_identity=False,
                        save_trajectories=False, max_iterations=2, max_tokens=2048,
                        run_budget_seconds=240, fallback_model=None,
                        request_overrides={'temperature': 0})
    if agent.tools:
        raise PolicyError('Hermes unexpectedly enabled tools')
    def deny(*args, **kwargs):
        raise PolicyError('Tool execution forbidden in proposal mode')
    agent._execute_tool_calls = deny
    result = agent.run_conversation(user_message=query)
    if not isinstance(result, dict) or result.get('error'):
        raise PolicyError('Hermes conversation failed')
    for message in result.get('messages', []):
        if message.get('role') == 'tool' or message.get('tool_calls'):
            raise PolicyError('Unexpected tool invocation')
    value = strict_json(result.get('final_response'))
    if req['role'] == 'smoke':
        if value != {'ready': True} or type(value['ready']) is not bool:
            raise PolicyError('Smoke response invalid')
    else:
        validate_proposal(req['role'], value)
    return value


def main():
    try:
        if not Path('/.dockerenv').exists() or os.geteuid() != 10001:
            raise PolicyError('Hermes worker must run in its unprivileged container')
        raw = sys.stdin.buffer.read(32769)
        if len(raw) > 32768:
            raise PolicyError('Request too large')
        req = strict_json(raw.decode('utf-8'))
        prompt(req)
        # The only runtime model endpoint is on the private Docker network.
        with urlopen('http://model:11434/api/tags', timeout=10) as response:
            body = response.read(1048577)
        if len(body) > 1048576:
            raise PolicyError('Model inventory too large')
        models = json.loads(body)['models']
        selected = [x for x in models if x.get('name') == MODEL]
        if len(selected) != 1 or selected[0].get('digest') != MODEL_DIGEST:
            raise PolicyError('Expected model missing or digest changed; preload the pinned model')
        home = Path(os.environ['HERMES_HOME'])
        home.mkdir(parents=True, exist_ok=True)
        (home / 'config.yaml').write_text('model:\n  context_length: 64000\n  ollama_num_ctx: 64000\n', encoding='utf-8')
        with contextlib.redirect_stdout(sys.stderr):
            sys.path.insert(0, '/opt/hermes')
            from run_agent import AIAgent
            value = invoke(req, AIAgent)
        print(json.dumps({'schema_version': 1, 'role': req['role'], 'request_sha256': digest(req),
                          'hermes_revision': HERMES_REVISION, 'model': MODEL,
                          'model_digest': selected[0]['digest'], 'tools': [], 'proposal': value}))
        return 0
    except Exception as exc:
        print(f'BLOCKED: {type(exc).__name__}: {str(exc)[:1500]}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
