"""Input bootstrap inside an ephemeral container; never run user jobs on host."""
import os
from pathlib import Path
import sys
from .job_contract import MAX_PAYLOAD, parse_job
from .policy import PolicyError


def _write_job_files(root: Path, job: dict) -> None:
    """Materialize validated Python files in an already-empty private tmpfs."""
    for name, source in job['files'].items():
        # Schema v1 accepts only flat files. Schema v2 permits bounded Python
        # package paths validated by parse_job. No source runs during staging.
        destination = root / name
        if job['schema_version'] == 2:
            destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('x', encoding='utf-8', newline='\n') as f:
            f.write(source)


def main():
    if sys.platform != 'linux' or not Path('/.dockerenv').is_file() or os.geteuid() != 10001:
        raise PolicyError('Worker requires the configured non-root Docker container')
    job = parse_job(sys.stdin.buffer.read(MAX_PAYLOAD + 1))
    root = Path('/work')
    # /work is a fresh size-limited tmpfs, not a host/repository mount.
    if not root.is_dir() or any(root.iterdir()):
        raise PolicyError('Expected empty /work')
    _write_job_files(root, job)
    os.chdir(root)
    program = 'import sys,runpy;sys.path.insert(0,"/work");runpy.run_path("/work/task.py",run_name="__main__")'
    # Replace bootstrap: target exit status is the process exit status.
    os.execv(sys.executable, [sys.executable, '-I', '-B', '-c', program])

if __name__ == '__main__':
    try:
        main()
    except (PolicyError, OSError) as e:
        print('WORKER_BLOCKED: ' + str(e), file=sys.stderr)
        raise SystemExit(125)
