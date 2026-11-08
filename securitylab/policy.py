"""Policy boundaries. Path guards do not constitute an OS sandbox."""
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re

class PolicyError(ValueError):
    pass

@dataclass(frozen=True)
class Limits:
    timeout: int = 20
    max_attempts: int = 3
    output_bytes: int = 65536
    max_context_chars: int = 24000
    max_reply_chars: int = 16000

    def __post_init__(self):
        if not 1 <= self.timeout <= 300 or not 1 <= self.max_attempts <= 10:
            raise PolicyError("Invalid time/attempt limit")
        if not 1024 <= self.output_bytes <= 1048576:
            raise PolicyError("Invalid output limit")
        if not 100 <= self.max_context_chars <= 100000 or not 100 <= self.max_reply_chars <= 100000:
            raise PolicyError("Invalid context/reply limit")


def run_id(value: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{32}", value):
        raise PolicyError("Invalid run ID")
    return value


def safe_path(root: Path, relative: str) -> Path:
    p = PurePosixPath(relative)
    if not relative or "\\" in relative or ":" in relative or p.is_absolute() or any(x in {"..", ".git"} for x in p.parts):
        raise PolicyError("Path not allowed")
    root = root.resolve()
    path = root.joinpath(*p.parts)
    cursor = root
    for part in p.parts:
        cursor /= part
        if cursor.is_symlink():
            raise PolicyError("Symlinks are not allowed")
    if not path.resolve().is_relative_to(root):
        raise PolicyError("Path escaped workspace")
    return path


def permit(role: str, action: str) -> None:
    allowed = {"red": {"read", "propose_finding"}, "blue": {"read", "propose_patch"}}
    if action not in allowed.get(role, set()):
        raise PolicyError(f"Role {role} cannot {action}")
