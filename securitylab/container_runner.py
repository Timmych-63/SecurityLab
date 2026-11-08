"""Trusted host broker. Docker control never enters the job container."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid
from .job_contract import job_bytes, parse_job, MAX_PAYLOAD
from .policy import Limits, PolicyError
from .process import execute
from .storage import atomic_text

IMAGE_ID = re.compile(r'sha256:[a-f0-9]{64}')
NAME = re.compile(r'securitylab-job-[a-f0-9]{32}')


def create_args(image_id, name):
    if not IMAGE_ID.fullmatch(image_id) or not NAME.fullmatch(name):
        raise PolicyError('Invalid immutable image ID or generated container name')
    return ['create', '--name', name, '--label', 'securitylab.ephemeral=true',
            '--interactive', '--init', '--network', 'none', '--read-only',
            '--user', '10001:10001', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true', '--pids-limit', '64',
            '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
            '--log-driver', 'none', '--restart', 'no',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m',
            '--tmpfs', '/work:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=0700',
            '--entrypoint', 'python', image_id, '-m', 'securitylab.container_worker']


class DockerBroker:
    def __init__(self, cwd: Path, executor=execute):
        self.cwd = cwd.resolve()
        self.execute = executor
        # Resolve once and explicitly pin the endpoint for every subsequent call.
        response = executor(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'],
                            self.cwd, Limits())
        endpoint = response.stdout.strip()
        if not response.passed or not endpoint.startswith(('unix:///', 'npipe://')) or any(c.isspace() for c in endpoint):
            raise PolicyError('A local Unix socket / Windows named pipe Docker endpoint is required')
        self.prefix = ['docker', '--host', endpoint]
        # No automatic model/image download and no arbitrary image selection from a job.
        details = json.loads(self.call(['image', 'inspect', 'securitylab-demo:local']).stdout)
        if len(details) != 1 or not IMAGE_ID.fullmatch(details[0].get('Id', '')):
            raise PolicyError('Cannot pin image ID')
        if details[0].get('Config', {}).get('Volumes'):
            raise PolicyError('Images with implicit volumes are not allowed')
        self.image_id = details[0]['Id']

    def call(self, args, *, check=True, limits=None, input_data=None, stop=None):
        options = {"input_data": input_data}
        if stop is not None:
            options["stop"] = stop
        r = self.execute(self.prefix + args, self.cwd, limits or Limits(), **options)
        if check and not r.passed:
            raise PolicyError('Docker command failed: ' + r.stderr[:1000])
        return r

    def run(self, payload: bytes, output: Path, limits=Limits(), *, binding=None, stop=None):
        parse_job(payload)  # Reject invalid payloads before invoking Docker.
        rid = uuid.uuid4().hex
        name = 'securitylab-job-' + rid
        record = {'schema_version': 1, 'id': rid, 'container': name, 'image_id': self.image_id,
                  'payload_sha256': hashlib.sha256(payload).hexdigest(), 'status': 'BLOCKED',
                  'output_trust': 'UNTRUSTED_JOB_OUTPUT; not proof of a fixed vulnerability',
                  'cleanup': 'NOT_TESTED', 'binding': dict(binding) if binding is not None else None}
        # Durable intent allows diagnosis if the host process is killed before finally.
        atomic_text(output / (rid + '.json'), json.dumps(record, ensure_ascii=False, indent=2))
        attempted_create = False
        try:
            if stop is not None and stop():
                record["status"] = "CANCELLED"
                record["cleanup"] = "PASS"
                return record
            attempted_create = True
            self.call(create_args(self.image_id, name))
            # Protect against unexpected Docker defaults/mounts before execution.
            inspect = json.loads(self.call(['inspect', name]).stdout)[0]
            host = inspect['HostConfig']
            if (inspect['Config']['Image'] != self.image_id or inspect['Config']['User'] != '10001:10001'
                or host.get('Privileged') is not False or host.get('NetworkMode') != 'none'
                or host.get('ReadonlyRootfs') is not True or host.get('Binds')
                or set(host.get('CapDrop') or []) != {'ALL'}
                or not any(x in ('no-new-privileges', 'no-new-privileges:true') for x in host.get('SecurityOpt', []))
                or host.get('Memory') != 536870912 or host.get('MemorySwap') != 536870912
                or host.get('NanoCpus') != 1000000000 or host.get('PidsLimit') != 64
                or host.get('Devices') or host.get('DeviceRequests')
                or set(host.get('Tmpfs') or {}) != {'/tmp', '/work'}
                or host.get('PidMode') == 'host' or host.get('IpcMode') == 'host'
                or any(m.get('Type') in {'bind', 'volume'} for m in inspect.get('Mounts', []))):
                raise PolicyError('Container inspect rejected unsafe settings')
            record['execution'] = self.call(['start', '--attach', '--interactive', name],
                                           check=False, limits=limits, input_data=payload, stop=stop).data()
            r = record['execution']
            if r['timed_out'] or r['cancelled'] or r['truncated']:
                record['status'] = 'TIMEOUT' if r['timed_out'] else ('CANCELLED' if r['cancelled'] else 'OUTPUT_LIMIT')
            else:
                state = json.loads(self.call(['inspect', '--format', '{{json .State}}', name]).stdout)
                record['container_state'] = state
                if state.get('Running') is not False:
                    raise PolicyError('Container still running after attach exited')
                if state.get('OOMKilled'):
                    record['status'] = 'RESOURCE_LIMIT'
                elif state.get('Error'):
                    record['status'] = 'BLOCKED'
                elif type(state.get('ExitCode')) is not int:
                    raise PolicyError('Missing exit status')
                elif r['returncode'] != state['ExitCode']:
                    record['status'] = 'TRANSPORT_ERROR'
                else:
                    record['status'] = 'COMPLETED' if state['ExitCode'] == 0 else 'NONZERO_EXIT'
        except (PolicyError, OSError, ValueError, KeyError, TypeError, IndexError) as e:
            record['status'] = 'BLOCKED'
            record['error'] = str(e)[:2000]
        except KeyboardInterrupt:
            record['status'] = 'CANCELLED'
        finally:
            if attempted_create:
                try:
                    removed = self.call(['rm', '--force', name], check=False)
                    # Check via daemon list, not an ambiguous nonzero inspect result.
                    remaining = self.call(['ps', '--all', '--quiet', '--filter', 'name=^/' + name + '$'])
                    record['cleanup'] = 'PASS' if not remaining.stdout.strip() else 'FAIL'
                    if not removed.passed:
                        record['cleanup_note'] = removed.stderr[:1000]
                except (PolicyError, OSError) as e:
                    record['cleanup'] = 'FAIL'
                    record['cleanup_error'] = str(e)[:1000]
                if record['cleanup'] != 'PASS':
                    record['status'] = 'CLEANUP_FAILED'
            atomic_text(output / (rid + '.json'), json.dumps(record, ensure_ascii=False, indent=2))
        return record


def self_test(broker, output):
    jobs = [
        ('normal', 'print("S2_EXECUTED")', 'COMPLETED', Limits()),
        ('nonzero', 'raise SystemExit(7)', 'NONZERO_EXIT', Limits()),
        ('timeout', 'import time; print("S2_TIMEOUT_STARTED", flush=True); time.sleep(60)', 'TIMEOUT', Limits(timeout=5)),
        ('output_limit', 'print("X"*200000)', 'OUTPUT_LIMIT', Limits(output_bytes=4096)),
        ('boundaries', '''import errno, os, pathlib, socket
assert os.geteuid() == 10001
assert not pathlib.Path('/data/state.sqlite3').exists()
assert not pathlib.Path('/var/run/docker.sock').exists()
try:
    pathlib.Path('/app/s2_probe').write_text('x', encoding='utf-8')
except OSError as e:
    assert e.errno in (errno.EROFS, errno.EACCES)
else:
    raise AssertionError('Application tree writable')
assert set(name for _,name in socket.if_nameindex()) == {'lo'}
with socket.socket() as s:
    s.settimeout(1)
    assert s.connect_ex(('192.0.2.1',443)) in (errno.ENETUNREACH,errno.EHOSTUNREACH)
print('S2_BOUNDARIES_OK')
''', 'COMPLETED', Limits())]
    results = []
    for name, code, expected, limits in jobs:
        record = broker.run(job_bytes({'task.py': code}), output, limits)
        passed = record['status'] == expected and record['cleanup'] == 'PASS'
        if name == 'normal':
            passed = passed and record.get('execution', {}).get('stdout', '').strip() == 'S2_EXECUTED'
        if name == 'timeout':
            passed = passed and 'S2_TIMEOUT_STARTED' in record.get('execution', {}).get('stdout', '')
        if name == 'boundaries':
            passed = passed and record.get('execution', {}).get('stdout', '').strip() == 'S2_BOUNDARIES_OK'
        if name == 'nonzero':
            passed = passed and record.get('container_state', {}).get('ExitCode') == 7
        results.append({'scenario': name, 'status': 'PASS' if passed else 'FAIL',
                        'observed': record['status'], 'cleanup': record['cleanup'], 'record': record['id']})
        if record['cleanup'] != 'PASS' or record['status'] == 'BLOCKED':
            break
    summary = {'status': 'PASS' if len(results) == len(jobs) and all(r['status'] == 'PASS' for r in results) else 'FAIL',
               'scenarios': results, 'scope': 'fixed broker self-tests, no AI, no arbitrary project acceptance'}
    atomic_text(output / 'self-test.json', json.dumps(summary, indent=2))
    return summary


def main(argv=None):
    p = argparse.ArgumentParser(description='S2 isolated Python runner; trusted host command only')
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--self-test', action='store_true')
    group.add_argument('--job', type=Path, help='Explicitly authorized synthetic Python job JSON')
    p.add_argument('--output', type=Path, default=Path('.securitylab/isolated_runs'))
    args = p.parse_args(argv)
    try:
        payload = None
        if args.job:
            with args.job.open('rb') as f:
                payload = f.read(MAX_PAYLOAD + 1)
            parse_job(payload)
        broker = DockerBroker(Path.cwd())
        result = self_test(broker, args.output) if args.self_test else broker.run(payload, args.output)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result['status'] in {'PASS', 'COMPLETED'} else 2
    except (PolicyError, OSError, ValueError) as e:
        print(json.dumps({'status': 'BLOCKED', 'error': str(e)}, ensure_ascii=False))
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
