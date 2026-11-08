"""Bounded checks for the demo container. Not a container escape certification."""
import errno
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import uuid
from .storage import atomic_text


def mount_options(text, target):
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[1] == target:
            return set(fields[3].split(','))
    return set()


def evaluate(s):
    checks = []
    def check(name, value, predicate):
        if value is None:
            status = 'BLOCKED'
        else:
            try:
                status = 'PASS' if predicate(value) else 'FAIL'
            except (ValueError, TypeError, IndexError, ZeroDivisionError):
                status = 'FAIL'
        checks.append({'check': name, 'status': status, 'observed': value})
    check('non_root_uid', s.get('uid'), lambda x: x == 10001)
    for key in ('CapEff', 'CapPrm', 'CapBnd'):
        check(key, s.get(key), lambda x: int(x, 16) == 0)
    check('no_new_privileges', s.get('NoNewPrivs'), lambda x: x == '1')
    check('seccomp_filter', s.get('Seccomp'), lambda x: x == '2')
    check('network_loopback_only', s.get('interfaces'), lambda x: set(x) == {'lo'})
    check('outbound_route_absent', s.get('network_errno'), lambda x: x in (errno.ENETUNREACH, errno.EHOSTUNREACH))
    check('root_readonly', s.get('root_options'), lambda x: 'ro' in x)
    check('tmp_mount_restrictions', s.get('tmp_options'), lambda x: {'noexec','nosuid','nodev'} <= set(x))
    check('data_writable', s.get('data_writable'), lambda x: x is True)
    check('tmp_writable', s.get('tmp_writable'), lambda x: x is True)
    check('docker_socket_absent', s.get('docker_socket_absent'), lambda x: x is True)
    check('memory_max_512MiB', s.get('memory.max'), lambda x: 0 < int(x) <= 512*1024*1024)
    check('pids_max_64', s.get('pids.max'), lambda x: 0 < int(x) <= 64)
    def cpu_limited(x):
        quota, period = x.split()
        return 0 < int(quota) / int(period) <= 1
    check('cpu_max_one_core', s.get('cpu.max'), cpu_limited)
    overall = 'FAIL' if any(c['status'] == 'FAIL' for c in checks) else (
        'BLOCKED' if any(c['status'] == 'BLOCKED' for c in checks) else 'PASS')
    return {'schema_version': 1, 'status': overall, 'checks': checks,
            'scope': 'demo container configuration and bounded probes only',
            'limitations': ['Not a proof of resistance to container escapes',
                            'Resource ceilings read from cgroup v2; no exhaustion stress test',
                            'No universal untrusted-code runner or AI permissions certification']}


def collect():
    def read(path):
        try:
            return Path(path).read_text(encoding='utf-8').strip()
        except OSError:
            return None
    s = {'uid': os.geteuid()}
    status = read('/proc/self/status')
    if status:
        entries = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
        for key in ('CapEff', 'CapPrm', 'CapBnd', 'NoNewPrivs', 'Seccomp'):
            s[key] = entries.get(key, '').strip() or None
    mounts = read('/proc/mounts')
    for target, key in (('/', 'root_options'), ('/tmp', 'tmp_options')):
        s[key] = sorted(mount_options(mounts, target)) if mounts is not None else None
    try:
        s['interfaces'] = [name for _, name in socket.if_nameindex()]
    except OSError:
        s['interfaces'] = None
    # No attempt is made when a non-loopback interface is present.
    # TEST-NET address is reserved for documentation, not a real service.
    if s['interfaces'] is not None and set(s['interfaces']) == {'lo'}:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                s['network_errno'] = sock.connect_ex(('192.0.2.1', 443))
        except OSError as e:
            s['network_errno'] = e.errno
    for path, key in (('/data', 'data_writable'), ('/tmp', 'tmp_writable')):
        try:
            with tempfile.TemporaryFile(dir=path) as f:
                f.write(b'securitylab-check'); f.flush()
            s[key] = True
        except OSError:
            s[key] = False
    s['docker_socket_absent'] = not any(Path(p).exists() for p in (
        '/var/run/docker.sock', '/run/docker.sock', '/run/podman/podman.sock'))
    for key in ('memory.max', 'pids.max', 'cpu.max'):
        s[key] = read('/sys/fs/cgroup/' + key)
    return s


def main():
    if sys.platform != 'linux' or not Path('/.dockerenv').is_file():
        print(json.dumps({'status': 'BLOCKED', 'reason': 'Run this check inside the demo Docker container'}))
        return 2
    result = evaluate(collect())
    result['id'] = uuid.uuid4().hex
    try:
        path = Path('/data/isolation_checks') / (result['id'] + '.json')
        atomic_text(path, json.dumps(result, indent=2))
        result['saved_report'] = str(path)
    except OSError as e:
        result['status'] = 'FAIL'
        result['save_error'] = str(e)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 2

if __name__ == '__main__':
    raise SystemExit(main())
