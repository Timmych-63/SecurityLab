"""Host-side bounded Hermes transport; no shell or state access granted to AI."""
import json
from dataclasses import dataclass
from pathlib import Path
import uuid
import sys
from .ai_contract import HERMES_REVISION, MODEL, MODEL_DIGEST, digest, strict_json
from .proposal_modes import proposal_prompt, proposal_validate, proposal_retry
from .discovery_contract import TASK as DISCOVERY_TASK
from .review_contract import TASK as REVIEW_TASK
from .research_contract import TASK_RED as RESEARCH_RED_TASK
from .research_contract import TASK_BLUE as RESEARCH_BLUE_TASK
_RETRYABLE_TASKS = (DISCOVERY_TASK, REVIEW_TASK, RESEARCH_RED_TASK, RESEARCH_BLUE_TASK)
from .container_runner import IMAGE_ID
from .policy import Limits, PolicyError
from .process import execute
from .storage import atomic_text

from .ai_config import AIConfig, load_config

NETWORK = 'securitylab-ai-private'


@dataclass(frozen=True)
class AIProcessLimits:
    # Only the trusted, tool-free model worker gets this longer deadline.
    timeout: int = 1200
    output_bytes: int = 131072

    def __post_init__(self):
        if type(self.timeout) is not int or not 1 <= self.timeout <= 1200:
            raise PolicyError('Invalid AI timeout')
        Limits(output_bytes=self.output_bytes)



def validate_envelope(req, value, config=None):
    config = config or AIConfig()
    expected = {'schema_version', 'role', 'request_sha256', 'hermes_revision', 'model', 'model_digest', 'tools', 'proposal'}
    if (not isinstance(value, dict) or set(value) != expected or type(value['schema_version']) is not int
        or value['schema_version'] != 1 or value['role'] != req['role']
        or value['request_sha256'] != digest(req) or value['hermes_revision'] != HERMES_REVISION
        or value['model'] != config.model or value['tools'] != []
        or not isinstance(value['model_digest'], str) or len(value['model_digest']) != 64
        or any(x not in '0123456789abcdef' for x in value['model_digest'])
        or value['model_digest'] != config.model_digest):
        raise PolicyError('Invalid Hermes response binding/configuration')
    proposal = value['proposal']
    if req['role'] == 'smoke':
        if not isinstance(proposal, dict) or proposal != {'ready': True} or type(proposal['ready']) is not bool:
            raise PolicyError('Invalid model smoke reply')
    else:
        proposal_validate(req, proposal)
    return proposal


class ProposalRejected(PolicyError):
    def __init__(self, message, previous, proposal=None, receipt_id=None):
        super().__init__(message)
        self.previous = previous
        self.proposal = proposal
        self.receipt_id = receipt_id
        self.cleanup_passed = False


def rejected_reply(stderr, role, attempt):
    raw = decision = proposal = None
    for line in stderr.splitlines():
        try:
            if line.startswith('AI_RESPONSE_JSON='):
                raw = json.loads(line[len('AI_RESPONSE_JSON='):])
            if line.startswith('AI_ATTEMPT_JSON='):
                decision = json.loads(line[len('AI_ATTEMPT_JSON='):])
            if line.startswith('AI_PROPOSAL_JSON='):
                proposal = json.loads(line[len('AI_PROPOSAL_JSON='):])
        except ValueError:
            return None
    if (isinstance(raw, str) and len(raw.encode('utf-8')) <= 16000
        and isinstance(decision, dict) and decision.get('role') == role
        and decision.get('attempt') == attempt and decision.get('status') == 'REJECTED'):
        reason = decision.get('reason')
        return raw, (reason if isinstance(reason, str) and reason else ''), proposal
    return None


class HermesAdapter:
    def __init__(self, cwd, output, executor=execute, config=None):
        self.config = config or load_config()
        self.cwd, self.output, self.execute = Path(cwd).resolve(), Path(output), executor
        r = executor(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'], self.cwd, Limits())
        endpoint = r.stdout.strip()
        if not r.passed or not endpoint.startswith(('unix:///', 'npipe://')) or any(c.isspace() for c in endpoint):
            raise PolicyError('Local Docker endpoint required')
        self.prefix = ['docker', '--host', endpoint]
        image = json.loads(self.call(['image', 'inspect', 'securitylab-hermes:s4']).stdout)[0]
        self.image = image['Id']
        if not IMAGE_ID.fullmatch(self.image) or image.get('Config', {}).get('Volumes'):
            raise PolicyError('Unsafe Hermes image')
        network = json.loads(self.call(['network', 'inspect', self.config.network]).stdout)[0]
        if network.get('Internal') is not True or network.get('Driver') != 'bridge':
            raise PolicyError('Private internal model network required')

    def call(self, args, check=True, **kwargs):
        result = self.execute(self.prefix + args, self.cwd, kwargs.pop('limits', Limits()), **kwargs)
        if check and not result.passed:
            raise PolicyError('Docker: ' + result.stderr[:1500])
        return result

    def ask(self, req, stop=lambda: False):
        proposal_prompt(req)
        try:
            return self._ask_once(req, stop)
        except ProposalRejected as exc:
            if (req['role'] != 'blue' and req.get('task') not in _RETRYABLE_TASKS) or 'retry' in req or not exc.cleanup_passed or stop():
                raise
            print(f"{req['role']}: proposal rejected; starting final corrective attempt.", file=sys.stderr, flush=True)
            return self._ask_once(proposal_retry(req, exc.previous), stop)

    def _ask_once(self, req, stop):
        proposal_prompt(req)
        attempt = 2 if 'retry' in req else 1
        print(f"{req['role']}: attempt {attempt}, timeout {self.config.timeout_seconds} seconds", file=sys.stderr, flush=True)
        identity = uuid.uuid4().hex
        name = 'securitylab-ai-' + identity
        path = self.output / (identity + '.json')
        record = {'id': identity, 'role': req['role'], 'request_sha256': digest(req), 'image_id': self.image,
                  'container': name, 'attempt': attempt, 'status': 'BLOCKED', 'cleanup': 'NOT_TESTED',
                  'trust': 'AI proposal, not vulnerability evidence',
                  'ai_config': self.config.data(), 'ai_config_sha256': self.config.sha256}
        atomic_text(path, json.dumps(record, indent=2))
        attempted = False
        failure = None
        try:
            if stop():
                raise PolicyError('AI call cancelled')
            attempted = True
            self.call(['create', '--name', name, '--label', 'securitylab.ai.ephemeral=true', '-i', '--init',
                       '--network', self.config.network, '--read-only', '--user', '10001:10001', '--cap-drop', 'ALL',
                       '--security-opt', 'no-new-privileges:true', '--memory', '1536m', '--memory-swap', '1536m',
                       '--pids-limit', '128', '--cpus', '1', '--log-driver', 'none', '--restart', 'no',
                       '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=128m',
                       '--env', 'SECURITYLAB_AI_RUNTIME=' + json.dumps(self.config.data()), self.image])
            info = json.loads(self.call(['inspect', name]).stdout)[0]
            host = info['HostConfig']
            if (info['Config']['Image'] != self.image or info['Config']['User'] != '10001:10001'
                or host.get('ReadonlyRootfs') is not True or host.get('Privileged') is not False
                or host.get('NetworkMode') != self.config.network or host.get('Binds') or host.get('Devices')
                or host.get('DeviceRequests') or host.get('PidMode') == 'host' or host.get('IpcMode') == 'host'
                or set(host.get('CapDrop') or []) != {'ALL'} or host.get('CapAdd')
                or not any(x in ('no-new-privileges','no-new-privileges:true') for x in host.get('SecurityOpt', []))
                or host.get('Memory') != 1610612736 or host.get('MemorySwap') != 1610612736
                or host.get('PidsLimit') != 128 or host.get('NanoCpus') != 1000000000
                or set(host.get('Tmpfs') or {}) != {'/tmp'}
                or any(x.get('Type') in {'bind','volume'} for x in info.get('Mounts', []))):
                raise PolicyError('Unsafe Hermes container configuration')
            result = self.call(['start', '-a', '-i', name], check=False,
                               limits=AIProcessLimits(timeout=self.config.timeout_seconds),
                               input_data=json.dumps(req).encode(), stop=stop)
            record['execution'] = result.data()
            state = json.loads(self.call(['inspect', '--format', '{{json .State}}', name]).stdout)
            record['container_state'] = state
            reason = ('TIMEOUT' if result.timed_out else 'CANCELLED' if result.cancelled
                      else 'OUTPUT_LIMIT' if result.truncated else 'RESOURCE_LIMIT' if state.get('OOMKilled') else None)
            if reason:
                record['status'] = reason
                raise PolicyError(f"{req['role']} attempt {attempt}: {reason} after {result.duration}s")
            if (result.returncode == 2 and state.get('Running') is False and state.get('ExitCode') == 2
                and state.get('OOMKilled') is False and not state.get('Error')):
                rejected = rejected_reply(result.stderr, req['role'], attempt)
                if rejected is not None and (req['role'] == 'blue' or req.get('task') in _RETRYABLE_TASKS):
                    previous, reason, rejected_proposal = rejected
                    record['status'] = 'REJECTED'
                    message = f"{req['role']} attempt {attempt}: proposal rejected; see call receipt {path}"
                    if reason:
                        message += ': ' + reason[:300]
                    raise ProposalRejected(message, previous, proposal=rejected_proposal,
                                           receipt_id=identity)
            if (not result.passed or state.get('Running') is not False or state.get('OOMKilled') is not False
                or state.get('Error') or type(state.get('ExitCode')) is not int or state['ExitCode'] != 0):
                raise PolicyError('Hermes failed/interrupted: ' + result.stderr[-1500:])
            envelope = strict_json(result.stdout)
            proposal = validate_envelope(req, envelope, self.config)
            record.update(status='PROPOSED', response=envelope)
        except KeyboardInterrupt:
            record['status'] = 'CANCELLED'
            raise
        except Exception as exc:
            failure = exc
            record['error'] = str(exc)[:2000]
            raise
        finally:
            if attempted:
                try:
                    self.call(['rm', '-f', name], check=False)
                    remaining = self.call(['ps', '-aq', '--filter', 'name=^/' + name + '$'])
                    record['cleanup'] = 'PASS' if not remaining.stdout.strip() else 'FAIL'
                except Exception as exc:
                    record['cleanup'], record['cleanup_error'] = 'FAIL', str(exc)[:1000]
            else:
                record['cleanup'] = 'PASS'
            if isinstance(failure, ProposalRejected):
                failure.cleanup_passed = record['cleanup'] == 'PASS'
            atomic_text(path, json.dumps(record, ensure_ascii=False, indent=2))
        if record['cleanup'] != 'PASS':
            raise PolicyError('Hermes cleanup failed')
        return proposal, record
