"""A deliberately small Python-only contract. No shell/image/mount fields."""
import json
import re
from .policy import PolicyError

MAX_PAYLOAD = 262144

def parse_job(raw: bytes):
    if len(raw) > MAX_PAYLOAD:
        raise PolicyError('Job exceeds 256 KiB')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PolicyError('Duplicate JSON key')
            result[key] = value
        return result
    try:
        job = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as e:
        raise PolicyError('Invalid job JSON: ' + str(e)) from e
    if (not isinstance(job, dict) or set(job) != {'schema_version', 'files'} or
        type(job['schema_version']) is not int or job['schema_version'] not in (1, 2)):
        raise PolicyError('Unsupported job schema')
    files = job['files']
    if not isinstance(files, dict) or not 1 <= len(files) <= 32 or 'task.py' not in files:
        raise PolicyError('Expected 1..32 Python files including task.py')
    seen = set()
    for name, source in files.items():
        if not isinstance(name, str):
            raise PolicyError('Invalid Python filename')
        if job['schema_version'] == 1:
            allowed = re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}\.py', name)
        else:
            allowed = re.fullmatch(
                r'(?:[A-Za-z_][A-Za-z0-9_]{0,63}/){0,4}[A-Za-z_][A-Za-z0-9_]{0,63}\.py', name)
            if '__pycache__' in name.casefold().split('/'):
                allowed = False
        if not allowed:
            raise PolicyError('Unsafe or unsupported Python filename for job version')
        if name.casefold() in seen or not isinstance(source, str) or '\x00' in source:
            raise PolicyError('Duplicate filename or invalid source')
        seen.add(name.casefold())
    return job


def job_bytes(files, *, schema_version=1):
    raw = json.dumps({'schema_version': schema_version, 'files': files}, ensure_ascii=False).encode('utf-8')
    parse_job(raw)
    return raw
