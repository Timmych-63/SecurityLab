"""Trusted host Docker orchestration for a bounded, independent HTTP client.

Target and verifier are separate containers on an ephemeral *internal* network.
No host port publishing/mounts/privileged containers, no dependency installation.
The service payload enters its container via stdin, never Docker environment.
This is a limited proof of HTTP observation, not a universal Docker sandbox.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import uuid

from .container_runner import DockerBroker, IMAGE_ID, create_args
from .job_contract import parse_job
from .policy import Limits, PolicyError
from .storage import atomic_text

# Verifier is a constant developer-owned script in the pinned image's Python.
# It has no project source, Docker control, listener, or mounts.
VERIFIER_SCRIPT = r'''
import base64, hashlib, http.client, json, os, sys, time
cfg=json.loads(base64.b64decode(os.environ["SL_HTTP_CONTRACT"], validate=True).decode('utf-8'))
checks=cfg['checks']; nonce=cfg['nonce']
assert isinstance(checks,list) and 1 <= len(checks) <= 8
rows=[]
for item in checks:
    path=item['path']; expected=item['expected_status']; actual=None; failure=None
    actor=item.get('actor'); body=b''
    for attempt in range(14):
        try:
            conn=http.client.HTTPConnection('target',8000,timeout=1.5)
            try:
                headers={'Host':'target','Connection':'close'}
                if actor is not None: headers['X-Test-User']=actor
                conn.request('GET',path,headers=headers)
                res=conn.getresponse()
                actual=res.status
                body=res.read(4097)
            finally:
                conn.close()
            failure=None
            break
        except (OSError,TimeoutError,http.client.HTTPException) as e:
            failure=type(e).__name__
            if attempt<13: time.sleep(0.2)
    row={'path':path,'expected_status':expected,'actual_status':actual,
         'passed':actual==expected,'error':failure}
    if 'actor' in item:
        row.update(actor=actor, body_sha256=hashlib.sha256(body).hexdigest() if actual is not None else None,
                   body_bytes=len(body) if actual is not None else None,
                   body_truncated=len(body)>4096 if actual is not None else None)
    rows.append(row)
result={'schema_version':1,'nonce':nonce,'observations':rows}
print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
sys.exit(0 if all(x['passed'] for x in rows) else 1)
'''.strip()

NETWORK = re.compile(r'securitylab-http-[a-f0-9]{32}\Z')


def http_create_args(image_id: str, name: str, network: str, *, target: bool,
                     contract_b64: str | None = None) -> list[str]:
    if not NETWORK.fullmatch(network):
        raise PolicyError('Invalid generated HTTP Docker network name')
    args = create_args(image_id, name)
    args[args.index('--network') + 1] = network
    if target:
        args[args.index('--network') + 2:args.index('--network') + 2] = ['--network-alias', 'target']
    else:
        if not contract_b64 or len(contract_b64) > 8192 or not re.fullmatch(r'[A-Za-z0-9+/=]+', contract_b64):
            raise PolicyError('Invalid bounded verifier contract')
        at = args.index(image_id)
        args[at:at] = ['--env', 'SL_HTTP_CONTRACT=' + contract_b64]
        args[args.index(image_id) + 1:] = ['-I', '-B', '-c', VERIFIER_SCRIPT]
    return args


class ServiceAttachment:
    """Streaming docker start -ai. The only host subprocess is the Docker CLI."""
    def __init__(self, cmd: list[str], cwd: Path, payload: bytes):
        self.process = subprocess.Popen(cmd, cwd=cwd, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=os.name != 'nt')
        self.buffers = [bytearray(), bytearray()]
        self.overflow = False
        self.feed_error = None
        self.threads = []

        def drain(stream, buf):
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                room = max(0, 32768 - len(buf))
                buf.extend(chunk[:room])
                if len(chunk) > room:
                    self.overflow = True
            stream.close()

        def feed():
            try:
                self.process.stdin.write(payload)
                self.process.stdin.flush()
            except (OSError, ValueError) as exc:
                self.feed_error = str(exc)
            finally:
                try:
                    self.process.stdin.close()
                except OSError:
                    pass

        for stream, buf in zip((self.process.stdout, self.process.stderr), self.buffers):
            self.threads.append(threading.Thread(target=drain, args=(stream, buf), daemon=True))
        self.threads.append(threading.Thread(target=feed, daemon=True))
        for thread in self.threads:
            thread.start()

    def healthy_transport(self):
        if self.overflow or self.feed_error:
            raise PolicyError('HTTP service Docker attach output overflow or stdin failure')

    def close(self):
        if self.process.poll() is None:
            self.process.kill()  # Only the trusted Docker CLI; container separately rm -f.
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
        for thread in self.threads:
            thread.join(timeout=1)


class HTTPDockerBroker(DockerBroker):
    """Owns network, target and verifier lifetimes; no Docker socket in either."""
    target_image_tag = None  # stdlib S6.3b uses the original trusted demo image.

    def __init__(self, cwd: Path, executor=None, attachment_cls=ServiceAttachment):
        if executor is None:
            super().__init__(cwd)
        else:
            super().__init__(cwd, executor)
        self.attachment_cls = attachment_cls
        self.target_image_id = self.image_id
        if self.target_image_tag is not None:
            # Dependency preparation must happen *before* execution in a
            # developer-selected image. No pip/requirements/scripts from repos.
            data = json.loads(self.call(['image', 'inspect', self.target_image_tag]).stdout)
            if (not isinstance(data, list) or len(data) != 1 or
                not IMAGE_ID.fullmatch(data[0].get('Id', '')) or
                data[0].get('Config', {}).get('Volumes') or
                data[0].get('Config', {}).get('Labels', {}).get('org.securitylab.profile') !=
                    'fastapi-s63c-v1'):
                raise PolicyError('Missing or invalid pinned FastAPI runtime image')
            self.target_image_id = data[0]['Id']

    def _inspect_network(self, network):
        data = json.loads(self.call(['network', 'inspect', network]).stdout)
        if (not isinstance(data, list) or len(data) != 1 or
            data[0].get('Name') != network or data[0].get('Internal') is not True or
            data[0].get('Driver') != 'bridge' or data[0].get('Attachable') is not False or
            data[0].get('Ingress') is not False or
            bool(data[0].get('Containers'))):
            raise PolicyError('Ephemeral network is not an empty private internal bridge')

    def _inspect_container(self, name, network, *, expected_image_id=None):
        info = json.loads(self.call(['inspect', name]).stdout)
        if not isinstance(info, list) or len(info) != 1:
            raise PolicyError('Missing HTTP container inspect')
        details = info[0]
        cfg = details['Config']; hc = details['HostConfig']
        networks = details.get('NetworkSettings', {}).get('Networks', {})
        if (cfg.get('Image') != (expected_image_id or self.image_id) or cfg.get('User') != '10001:10001' or
            hc.get('Privileged') is not False or hc.get('NetworkMode') != network or
            hc.get('ReadonlyRootfs') is not True or hc.get('Binds') or
            hc.get('PortBindings') or cfg.get('ExposedPorts') or
            set(hc.get('CapDrop') or []) != {'ALL'} or
            not any(opt in ('no-new-privileges','no-new-privileges:true') for opt in hc.get('SecurityOpt', [])) or
            hc.get('Memory') != 536870912 or hc.get('MemorySwap') != 536870912 or
            hc.get('NanoCpus') != 1000000000 or hc.get('PidsLimit') != 64 or
            hc.get('Devices') or hc.get('DeviceRequests') or
            set(hc.get('Tmpfs') or {}) != {'/tmp', '/work'} or
            hc.get('PidMode') == 'host' or hc.get('IpcMode') == 'host' or
            any(m.get('Type') in {'bind','volume'} for m in details.get('Mounts', [])) or
            set(networks) != {network}):
            raise PolicyError('HTTP container inspect rejected unsafe settings')
        return details

    def run(self, payload: bytes, checks: list[dict], folder: Path, *, binding: dict,
            limits=Limits(), stop=None) -> dict:
        parse_job(payload)
        if not isinstance(checks, list) or not 1 <= len(checks) <= 8:
            raise PolicyError('Invalid HTTP check collection')
        for item in checks:
            if not isinstance(item,dict) or set(item) not in (
                    {'path','expected_status'}, {'path','expected_status','actor'}):
                raise PolicyError('Invalid bounded HTTP check fields')
            if (not isinstance(item['path'],str) or not re.fullmatch(r'/[A-Za-z0-9._~/?&=+!$(),;:@-]{0,240}', item['path']) or
                item['path'].startswith('//') or '/..' in item['path'] or
                type(item['expected_status']) is not int or not 200 <= item['expected_status'] <= 599):
                raise PolicyError('Invalid bounded HTTP path or status')
            if 'actor' in item and item['actor'] is not None and (not isinstance(item['actor'],str) or
                not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}', item['actor'], re.ASCII)):
                raise PolicyError('Invalid bounded synthetic actor')
        uuid_hex = uuid.uuid4().hex
        network = 'securitylab-http-' + uuid_hex
        target = 'securitylab-job-' + uuid.uuid4().hex
        verifier = 'securitylab-job-' + uuid.uuid4().hex
        contract = {'nonce': uuid.uuid4().hex, 'checks': checks}
        b64 = base64.b64encode(json.dumps(contract, separators=(',', ':')).encode()).decode()
        checks_hash = hashlib.sha256(json.dumps(checks, sort_keys=True,
                                  separators=(',', ':')).encode()).hexdigest()
        receipt = {'schema_version': 1, 'status': 'BLOCKED', 'cleanup': 'NOT_TESTED',
                   'binding': binding, 'source_payload_sha256': hashlib.sha256(payload).hexdigest(),
                   'checks_sha256': checks_hash, 'image_id': self.image_id,
                   'target_image_id': self.target_image_id,
                   'network_name': network, 'target_name': target, 'verifier_name': verifier,
                   'observations': []}
        output = folder / 'docker_receipt.json'
        atomic_text(output, json.dumps(receipt, ensure_ascii=False, indent=2))
        net_attempted = False; target_attempted = False; verifier_attempted = False
        attachment = None
        cleanup_errors = []
        try:
            def checkpoint():
                if stop is not None and stop(): raise PolicyError('HTTP verification cancelled by operator')
            checkpoint()
            net_attempted = True
            self.call(['network','create','--driver','bridge','--internal',
                       '--label','securitylab.ephemeral=true',network])
            self._inspect_network(network)
            checkpoint()
            target_attempted = True
            self.call(http_create_args(self.target_image_id,target,network,target=True))
            self._inspect_container(target,network,expected_image_id=self.target_image_id)
            checkpoint()
            verifier_attempted = True
            self.call(http_create_args(self.image_id,verifier,network,target=False,contract_b64=b64))
            self._inspect_container(verifier,network)
            # Service transport: source only via stdin, not env, volumes or host shell.
            checkpoint()
            attachment = self.attachment_cls(self.prefix + ['start','--attach','--interactive',target],
                                             self.cwd, payload)
            # Run a fixed independent HTTP client. It accepts only bounded contract JSON.
            r = self.call(['start','--attach',verifier],check=False,
                          limits=Limits(timeout=min(120,max(30,limits.timeout)),
                                        output_bytes=min(65536,limits.output_bytes)),
                          **({'stop':stop} if stop is not None else {}))
            attachment.healthy_transport()
            if r.timed_out or r.cancelled or r.truncated:
                raise PolicyError('HTTP verifier timed out, cancelled or exceeded output limit')
            daemon = json.loads(self.call(['inspect','--format','{{json .State}}',verifier]).stdout)
            if (daemon.get('Running') is not False or daemon.get('OOMKilled') is not False or
                daemon.get('Error') or type(daemon.get('ExitCode')) is not int or
                daemon['ExitCode'] != r.returncode or daemon['ExitCode'] not in (0,1)):
                raise PolicyError('Independent verifier daemon exit inconsistent')
            target_state = json.loads(self.call(['inspect','--format','{{json .State}}',target]).stdout)
            if target_state.get('Running') is not True or target_state.get('OOMKilled') is not False:
                raise PolicyError('HTTP target not running for verification')
            try:
                data = json.loads(r.stdout)
            except (ValueError,TypeError) as exc:
                raise PolicyError('Independent verifier returned invalid JSON') from exc
            if (not isinstance(data,dict) or set(data) != {'schema_version','nonce','observations'} or
                data.get('schema_version') != 1 or data['nonce'] != contract['nonce'] or
                not isinstance(data['observations'],list) or len(data['observations']) != len(checks)):
                raise PolicyError('Independent verifier output/binding invalid')
            for expected, actual in zip(checks,data['observations']):
                wanted = {'path','expected_status','actual_status','passed','error'}
                if 'actor' in expected:
                    wanted |= {'actor','body_sha256','body_bytes','body_truncated'}
                if (not isinstance(actual,dict) or set(actual) != wanted or
                    actual['path'] != expected['path'] or actual['expected_status'] != expected['expected_status'] or
                    (actual['actual_status'] is not None and (type(actual['actual_status']) is not int or
                    not 100 <= actual['actual_status'] <= 599)) or
                    (actual['actual_status'] is not None and actual.get('error') is not None) or
                    type(actual['passed']) is not bool or
                    actual['passed'] != (actual['actual_status'] == expected['expected_status'])):
                    raise PolicyError('Independent verifier check contradiction')
                if 'actor' in expected and (actual.get('actor') != expected['actor'] or
                    (actual['actual_status'] is not None and (
                        not isinstance(actual['body_sha256'],str) or
                        not re.fullmatch(r'[a-f0-9]{64}',actual['body_sha256']) or
                        type(actual['body_bytes']) is not int or not 0 <= actual['body_bytes'] <= 4097 or
                        type(actual['body_truncated']) is not bool or
                        actual['body_truncated'] != (actual['body_bytes'] > 4096)))):
                    raise PolicyError('Independent verifier actor/body evidence invalid')
            if any(row['actual_status'] is None for row in data['observations']):
                raise PolicyError('HTTP verifier could not obtain every response')
            all_pass = all(row['passed'] for row in data['observations'])
            if (r.returncode == 0) != all_pass:
                raise PolicyError('Verifier exit conflicts with observed checks')
            receipt['status'] = 'HTTP_CHECKS_PASSED' if all_pass else 'HTTP_CHECKS_FAILED'
            receipt['observations'] = data['observations']
            receipt['verifier_exit_code'] = r.returncode
            receipt['target_running_at_check'] = True
        except (PolicyError,OSError,KeyError,TypeError,ValueError,IndexError) as exc:
            receipt['status'] = 'BLOCKED'
            receipt['error'] = str(exc)[:2000]
        finally:
            # Kill both containers before killing the attached Docker CLI process.
            for attempted, name in ((verifier_attempted,verifier),(target_attempted,target)):
                if attempted:
                    try:
                        deleted = self.call(['rm','--force',name],check=False)
                        remaining = self.call(['ps','--all','--quiet','--filter','name=^/'+name+'$'])
                        if not deleted.passed or remaining.stdout.strip():
                            cleanup_errors.append('Container cleanup was not confirmed')
                    except (PolicyError,OSError) as exc:
                        cleanup_errors.append('Container cleanup failed: '+str(exc)[:160])
            if attachment is not None:
                try:
                    attachment.close()
                except (OSError,subprocess.TimeoutExpired) as exc:
                    cleanup_errors.append('Service attach cleanup failed: '+str(exc)[:160])
            if net_attempted:
                try:
                    deleted = self.call(['network','rm',network],check=False)
                    # Check existence with network ls, not an ambiguous inspect error.
                    remaining = self.call(['network','ls','--quiet','--filter','name=^'+network+'$'])
                    if not deleted.passed or remaining.stdout.strip():
                        cleanup_errors.append('Network cleanup was not confirmed')
                except (PolicyError,OSError) as exc:
                    cleanup_errors.append('Network cleanup failed: '+str(exc)[:160])
            receipt['cleanup'] = 'FAIL' if cleanup_errors else 'PASS'
            if cleanup_errors:
                receipt['status'] = 'BLOCKED'
                receipt['cleanup_errors'] = cleanup_errors[:4]
            atomic_text(output,json.dumps(receipt,ensure_ascii=False,indent=2))
        return receipt


class FastAPIHTTPDockerBroker(HTTPDockerBroker):
    """Explicit S6.3c adapter: baked dependencies, no runtime installation."""
    target_image_tag = 'securitylab-fastapi:local'
