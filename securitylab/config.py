from pathlib import Path
import tomllib
from .policy import Limits, PolicyError

def load_limits(path: Path | None) -> Limits:
    if path is None:
        return Limits()
    body = tomllib.loads(path.read_text(encoding='utf-8'))
    if set(body) != {'limits'} or not isinstance(body['limits'], dict):
        raise PolicyError('Configuration must contain only [limits]')
    allowed = {'timeout', 'max_attempts', 'output_bytes', 'max_context_chars', 'max_reply_chars'}
    values = body['limits']
    if not set(values) <= allowed or any(type(v) is not int for v in values.values()):
        raise PolicyError('Unknown option or non-integer limit')
    return Limits(**values)
