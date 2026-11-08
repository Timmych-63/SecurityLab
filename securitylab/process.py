"""Bounded process capture for trusted fixed commands, not a general sandbox."""
from dataclasses import dataclass, asdict
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from .policy import Limits

@dataclass
class Result:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    cancelled: bool
    truncated: bool
    duration: float

    @property
    def passed(self):
        return self.returncode == 0 and not (self.timed_out or self.cancelled or self.truncated)

    def data(self):
        return asdict(self)


def execute(argv: list[str], cwd: Path, limits: Limits, stop=lambda: False, env=None):
    started = time.monotonic()
    process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL, env=env, start_new_session=os.name != 'nt')
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    def drain(stream, buf):
        while chunk := stream.read(4096):
            room = max(0, limits.output_bytes - len(buf))
            buf.extend(chunk[:room])
            if len(chunk) > room:
                overflow.set()
        stream.close()
    threads = [threading.Thread(target=drain, args=(stream, buf), daemon=True)
               for stream, buf in zip((process.stdout, process.stderr), buffers)]
    for thread in threads:
        thread.start()
    timed_out = cancelled = False
    try:
        while process.poll() is None:
            timed_out = time.monotonic() - started >= limits.timeout
            cancelled = bool(stop())
            if timed_out or cancelled or overflow.is_set():
                break
            time.sleep(0.02)
    finally:
        # Kill remaining descendants on POSIX even if their leader exited.
        if os.name != 'nt':
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()  # Windows trusted fixtures do not create descendants.
        process.wait()
        for thread in threads:
            thread.join(timeout=2)
    if any(t.is_alive() for t in threads):
        overflow.set()
    return Result(argv, process.returncode, buffers[0].decode('utf-8', 'replace'),
                  buffers[1].decode('utf-8', 'replace'), timed_out, cancelled,
                  overflow.is_set(), round(time.monotonic() - started, 4))
