"""Operator-owned AI profile catalog. Never load settings from target repositories."""
from pathlib import Path
import re
import tomllib
from .ai_config import from_dict, load_config
from .policy import PolicyError

class Profiles:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.default = load_config()  # fail closed on invalid explicitly selected config

    def get(self, identity):
        if identity == 'default':
            return self.default
        if not isinstance(identity, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}', identity):
            raise PolicyError('Invalid AI profile ID')
        path = self.directory / (identity + '.toml')
        if path.is_symlink() or path.resolve().parent != self.directory:
            raise PolicyError('AI profile must be a regular operator-owned file')
        try:
            if path.stat().st_size > 16384:
                raise PolicyError('AI profile too large')
            doc = tomllib.loads(path.read_text(encoding='utf-8-sig'))
            if set(doc) != {'ai'}:
                raise PolicyError('Expected only [ai] table')
            return from_dict(doc['ai'])
        except (OSError, ValueError) as exc:
            raise PolicyError('Cannot load AI profile: ' + str(exc)) from exc

    def list(self):
        ids = ['default'] + sorted(p.stem for p in self.directory.glob('*.toml') if p.stem != 'default')
        rows = []
        for identity in ids[:100]:
            c = self.get(identity)  # invalid profiles are errors, not silently replaced
            rows.append(dict(id=identity, name=identity, model=c.model, digest=c.model_digest,
                server=c.server_url, network=c.network, contextTokens=c.context_tokens,
                maxOutputTokens=c.max_output_tokens, timeoutSeconds=c.timeout_seconds,
                configValid=True, modelPing=None, present=None, configurationSha256=c.sha256))
        return rows
