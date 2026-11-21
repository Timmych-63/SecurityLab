"""Validated operator AI settings, separate from untrusted project configuration."""
import json
import os
import re
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from .ai_contract import MODEL, MODEL_DIGEST, digest
from .policy import PolicyError

@dataclass(frozen=True)
class AIConfig:
    model: str = MODEL
    model_digest: str = MODEL_DIGEST
    server_url: str = 'http://model:11434'
    network: str = 'securitylab-ai-private'
    context_tokens: int = 64000
    max_output_tokens: int = 2048
    timeout_seconds: int = 1200
    frequency_penalty: float | None = None
    presence_penalty: float | None = None

    def __post_init__(self):
        for field, pattern in [('model', r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}'),
                               ('model_digest', r'[a-f0-9]{64}'),
                               ('network', r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}'),
                               ('server_url', r'http://[a-zA-Z][a-zA-Z0-9-]{0,62}:[0-9]{1,5}')]:
            value = getattr(self, field)
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                raise PolicyError('Invalid AI setting: ' + field)
        if not 1 <= int(self.server_url.rsplit(':', 1)[1]) <= 65535:
            raise PolicyError('Invalid AI server port')
        for field, low, high in [('context_tokens',64000,131072),
                                 ('max_output_tokens',256,4096),
                                 ('timeout_seconds',120,1200)]:
            value = getattr(self, field)
            if type(value) is not int or not low <= value <= high:
                raise PolicyError(f'Invalid AI {field}: required {low}..{high}')
        # Optional OpenAI-compatible sampling knobs the model server actually
        # implements on /v1/chat/completions (Ollama maps them onto its native
        # repeat suppression). Unset means: send nothing, keep server defaults.
        for field in ('frequency_penalty', 'presence_penalty'):
            value = getattr(self, field)
            if value is not None and (type(value) not in (int, float)
                                      or isinstance(value, bool) or not 0 <= value <= 2):
                raise PolicyError(f'Invalid AI {field}: optional number 0..2, or omit the key')

    def data(self):
        return asdict(self)

    @property
    def sha256(self):
        return digest(self.data())


def from_dict(value):
    if not isinstance(value, dict) or set(value) - set(AIConfig.__dataclass_fields__):
        raise PolicyError('Unknown AI configuration keys')
    if ('model' in value) != ('model_digest' in value):
        raise PolicyError('Set model and model_digest together')
    try:
        return AIConfig(**value)
    except TypeError as exc:
        raise PolicyError('Invalid AI configuration') from exc


def load_config():
    # Explicit operator-selected path only; never discover config inside a target repo.
    selected = os.environ.get('SECURITYLAB_AI_CONFIG')
    if not selected:
        return AIConfig()
    try:
        raw = Path(selected).read_bytes()
        if len(raw) > 16384:
            raise PolicyError('AI configuration too large')
        document = tomllib.loads(raw.decode('utf-8-sig'))
        if set(document) != {'ai'}:
            raise PolicyError('Expected only [ai] table')
        return from_dict(document['ai'])
    except (OSError, ValueError) as exc:
        raise PolicyError('Cannot load AI configuration: ' + str(exc)) from exc


if __name__ == '__main__':
    try:
        config = load_config()
        print(json.dumps({'status':'VALID', 'configuration':config.data(),
                          'sha256':config.sha256,
                          'scope':'Configuration only; server/model not contacted'}, indent=2))
    except PolicyError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
