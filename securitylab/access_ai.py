"""S7.2: AI-proposed one-module FastAPI fix, independently replayed in Docker.

No arbitrary scan, no AI tools, no writes to the input repository/snapshot,
no shell execution of its source on the host, and no automatic merge.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import sys
from pathlib import Path
import uuid

from .access_baseline import _classify, read_external_policy
from .access_contract import make_request, validate_reply
from .ai_contract import MODEL_DIGEST, digest
from .fastapi_probe import run_fastapi_http_observation
from .hermes_adapter import HermesAdapter
from .http_runner import FastAPIHTTPDockerBroker
from .job_contract import job_bytes
from .package_probe import _source_package
from .policy import Limits, PolicyError, safe_path
from .process import execute as execute_process
from .snapshots import _id, verify_snapshot
from .storage import atomic_text, worker_lock


def _sha(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def _jsonsha(value):
    return _sha(json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def _git(repo: Path, *arguments):
    # Never inherit host Git hooks, global configs, prompts or repo filters.
    env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT='0', GIT_AUTHOR_NAME='SecurityLab Verification',
        GIT_AUTHOR_EMAIL='verification@localhost',
        GIT_COMMITTER_NAME='SecurityLab Verification',
        GIT_COMMITTER_EMAIL='verification@localhost')
    cmd = ['git','-c','core.hooksPath='+os.devnull,'-c','commit.gpgsign=false',
           '-c','core.autocrlf=false','-c','filter.lfs.required=false',*arguments]
    result = execute_process(cmd, repo, Limits(timeout=20,output_bytes=65536), env=env)
    if not result.passed:
        raise PolicyError('Isolated Git operation failed: '+result.stderr[:750])
    return result.stdout.strip()


def _prepare_git(run_folder: Path, sources: dict[str,str], entry: str, run_id: str):
    target = run_folder / 'review_branch'
    target.mkdir(parents=True,exist_ok=False)
    for relative, content in sources.items():
        file = safe_path(target,relative)
        file.parent.mkdir(parents=True,exist_ok=True)
        file.write_bytes(content.encode('utf-8'))
    # No source repository metadata or uncontrolled files can be copied in.
    templates = run_folder / 'empty_git_template'
    templates.mkdir(exist_ok=False)
    _git(target,'init','-q','-b','main',f'--template={templates}')
    _git(target,'add','--',*sorted(sources))
    _git(target,'commit','-q','-m','SecurityLab trusted snapshot baseline')
    original = _git(target,'rev-parse','HEAD')
    branch = 'securitylab/fix-'+run_id
    _git(target,'switch','-q','-c',branch)
    if _git(target,'rev-parse','HEAD')!=original:
        raise PolicyError('Isolated Git branch diverged before patch')
    return target, branch, original


def _audit_ai_receipt(folder: Path, record: dict, proposal: dict):
    identity = record.get('id')
    if not isinstance(identity,str) or not re.fullmatch(r'[a-f0-9]{32}',identity):
        raise PolicyError('Invalid Hermes receipt ID')
    file = folder / (identity + '.json')
    raw = file.read_bytes()
    if len(raw)>131072:
        raise PolicyError('Hermes receipt exceeds audit bound')
    saved = json.loads(raw.decode('utf-8'))
    envelope = saved.get('response',{})
    if (saved != record or saved.get('status') != 'PROPOSED' or
        saved.get('cleanup') != 'PASS' or
        envelope.get('proposal') != proposal or
        envelope.get('model_digest') != MODEL_DIGEST or
        saved.get('request_sha256') != envelope.get('request_sha256') or
        envelope.get('tools') != []):
        raise PolicyError('Hermes proposal receipt modified or unverified')
    return _sha(raw)


def _observe(store, folder: Path, run_id: str, stage: str, snapshot_id: str,
             service: str, entry: str, module: str, sources: dict[str,str],
             policy: dict, policy_hash: str, manifest_hash: str,
             broker_factory, observer, limits):
    launcher = ('import uvicorn\n'
        + f"uvicorn.run({module + ':app'!r}, host='0.0.0.0', port=8000, workers=1, "
        + "log_level='warning', access_log=False)\n")
    payload = job_bytes({'task.py':launcher, **sources}, schema_version=2)
    checks = [{'path':c['path'],'expected_status':c['expected_status'],'actor':c['actor']}
              for c in policy['checks']]
    binding = {'run_id':run_id, 'stage':stage, 'snapshot_id':snapshot_id,
               'service':service, 'entry':entry, 'policy_sha256':policy_hash,
               'manifest_sha256':manifest_hash,'checks_sha256':_jsonsha(checks),
               'payload_sha256':_sha(payload), 'profile':'access-ai-s72-v1'}
    stage_dir = folder / stage
    observed = observer(stage_dir,payload,checks,binding,
                        broker_factory=broker_factory, limits=limits)
    status,verdict,finding,outcomes = _classify(policy,observed['observations'])
    report = {'stage':stage, 'status':status, 'security_verdict':verdict,
              'finding_status':finding, 'outcomes':outcomes,
              'observations':observed['observations'], 'binding':binding,
              'image_id':observed['image_id'], 'target_image_id':observed['target_image_id'],
              'cleanup':observed['cleanup'], 'receipt_sha256':observed['receipt_sha256']}
    atomic_text(stage_dir / 'summary.json',json.dumps(report,ensure_ascii=False,indent=2))
    return report


def run_access_ai(store, snapshot_id: str, entry: str, policy_path: Path, *,
                  service='.', execute=False, adapter_factory=HermesAdapter,
                  broker_factory=FastAPIHTTPDockerBroker,
                  observer=run_fastapi_http_observation, limits=Limits()):
    if execute is not True:
        raise PolicyError('S7.2 requires explicit --execute')
    sid = _id(snapshot_id)
    policy,policy_hash = read_external_policy(store,sid,policy_path)
    module,sources,package_hash,entry_hash,verified = _source_package(store,sid,service,entry)
    relative = '/'.join(entry.split('/')[len([] if service == '.' else service.split('/')):])
    if relative not in sources:
        raise PolicyError('S7.2 entry missing from selected service')
    original = sources[relative]
    if len(original.encode('utf-8'))>12000:
        raise PolicyError('S7.2 only supports entry modules up to 12 KiB')
    hints = [{'id':c['id'],'kind':c['kind'],'actor':c['actor'],
              'path':c['path'],'expected_status':c['expected_status']}
             for c in policy['checks']]
    run_id=uuid.uuid4().hex
    directory=store.root / 'access_ai' / run_id
    directory.mkdir(parents=True,exist_ok=False)
    output={'schema_version':1,'run_id':run_id,'mode':'S7_2_ACCESS_AI_SINGLE_MODULE',
            'snapshot_id':sid,'entry':entry,'service':service,
            'manifest_sha256':verified['manifest_sha256'],
            'package_sha256':package_hash,'source_sha256':entry_hash,
            'policy_sha256':policy_hash,'status':'BLOCKED',
            'finding_status':None,'security_verdict':'NOT_EVALUATED',
            'scope':'One selected FastAPI Python module, external operator policy, no auto-merge',
            'checks_total':len(hints),'stages':{},'ai_calls':[]}
    folder=store.root / 'ai'
    folder.mkdir(exist_ok=True)
    try:
        with worker_lock(folder):
            adapter = adapter_factory(Path.cwd(),directory/'calls')
            red,red_receipt=adapter.ask(make_request('red',entry,original,hints))
            validate_reply(make_request('red',entry,original,hints),red)
            output['red']={'file':red['file'],'check_id':red['check_id'],
                           'description':red['description'],'proposal_sha256':digest(red)}
            output['ai_calls'].append({'role':'red','id':red_receipt['id'],
                           'model_digest':red_receipt['response']['model_digest']})
            baseline=_observe(store,directory,run_id,'baseline',sid,service,entry,module,
                 sources,policy,policy_hash,verified['manifest_sha256'],
                 broker_factory,observer,limits)
            output['stages']['baseline']=baseline
            if baseline['status']!='ACCESS_POLICY_VIOLATION_REPRODUCED' or not any(
                x['id']==red['check_id'] and x['result']=='UNAUTHORIZED_BODY_MATCHES_CONTROL'
                for x in baseline['outcomes']):
                output['status']='NEEDS_REVIEW'
                output['error']='Independent baseline did not reproduce selected Red case'
                return output
            ai_audits = [(red_receipt, red, _audit_ai_receipt(directory/'calls',red_receipt,red))]
            def audit_progress():
                if verify_snapshot(store,sid)['manifest_sha256'] != verified['manifest_sha256']:
                    raise PolicyError('Source snapshot changed during verification')
                if read_external_policy(store,sid,policy_path)[1] != policy_hash:
                    raise PolicyError('Independent policy changed during verification')
                for receipt, proposal, sha in ai_audits:
                    if _audit_ai_receipt(directory/'calls',receipt,proposal) != sha:
                        raise PolicyError('Hermes receipt changed during independent verification')
                if len({(r['image_id'],r['target_image_id']) for r in output['stages'].values()}) != 1:
                    raise PolicyError('Docker images differed between baseline and candidate')
                for stage, report in output['stages'].items():
                    if report['cleanup'] != 'PASS':
                        raise PolicyError('Independent cleanup failed')
                    if json.loads((directory/stage/'summary.json').read_text('utf-8')) != report:
                        raise PolicyError('Independent stage summary changed')
                    if _sha((directory/stage/'docker_receipt.json').read_bytes()) != report['receipt_sha256']:
                        raise PolicyError('Independent Docker receipt changed')
                for attempt in output.get('candidates', []):
                    if _sha((directory/attempt['file']).read_bytes()) != attempt['sha256']:
                        raise PolicyError('Saved Blue candidate changed during verification')

            audit_progress()
            blue_req=make_request('blue',entry,original,hints,finding=red['check_id'])
            repo,branch,base_commit=_prepare_git(directory,sources,relative,run_id)
            candidate_file=safe_path(repo,relative)
            output['candidates']=[]
            for candidate_number in (1, 2):
                blue,blue_receipt=adapter.ask(blue_req)
                validate_reply(blue_req,blue)
                attempt = blue_receipt.get('attempt')
                if type(attempt) is not int or attempt not in (1,2) or (candidate_number == 2 and attempt != 2):
                    raise PolicyError('Invalid Blue attempt budget receipt')
                output['blue_attempts_used']=attempt
                output['ai_calls'].append({'role':'blue','id':blue_receipt['id'],
                               'model_digest':blue_receipt['response']['model_digest']})
                sha=_audit_ai_receipt(directory/'calls',blue_receipt,blue)
                ai_audits.append((blue_receipt,blue,sha))
                output['ai_receipt_sha256']={r['id']:h for r,p,h in ai_audits}
                candidate=blue['content']
                output['candidate_sha256']=_sha(candidate)
                saved_name=f'candidate_{candidate_number}.py'
                atomic_text(directory/saved_name,candidate)
                atomic_text(directory/'candidate.py',candidate)
                output['candidates'].append({'file':saved_name,'sha256':_sha(candidate),
                                            'call_id':blue_receipt['id']})
                candidate_file.write_bytes(candidate.encode('utf-8'))
                _git(repo,'diff','--check')
                if _git(repo,'diff','--name-only') != relative:
                    raise PolicyError('Patch attempted to modify an unselected file')
                patched=dict(sources,**{relative:candidate})
                stage='candidate' if candidate_number == 1 else 'candidate_retry'
                first=_observe(store,directory,run_id,stage,sid,service,entry,module,
                    patched,policy,policy_hash,verified['manifest_sha256'],broker_factory,observer,limits)
                output['stages'][stage]=first
                audit_progress()
                if first['status']=='ACCESS_POLICY_MATCHED':
                    break
                if first['status']!='ACCESS_POLICY_VIOLATION_REPRODUCED' or attempt == 2:
                    output['status']='NEEDS_REVIEW'
                    output['error']='Blue candidate does not satisfy independent policy; no corrective budget or reproducible case'
                    return output
                evidence=[{'id':c['id'],'expected_status':c['expected_status'],
                           'actual_status':a['actual_status']}
                          for c,a in zip(policy['checks'],first['observations'])]
                blue_req=make_request('blue',entry,candidate,hints,finding=red['check_id'],
                    retry='Independent candidate verification failed',evidence=evidence)
                print('Blue: independent policy violation persists; final corrective attempt (2/2).',
                      file=sys.stderr,flush=True)
            second=_observe(store,directory,run_id,'recheck',sid,service,entry,module,
                patched,policy,policy_hash,verified['manifest_sha256'],broker_factory,observer,limits)
            output['stages']['recheck']=second
            if second['status']!='ACCESS_POLICY_MATCHED':
                output['status']='NEEDS_REVIEW'
                output['error']='Independent repeat did not confirm candidate result'
                return output
            if len({(row['image_id'],row['target_image_id']) for row in output['stages'].values()}) != 1:
                raise PolicyError('Docker images differed between baseline and candidate')
            if _sha(candidate_file.read_bytes()) != _sha(candidate):
                raise PolicyError('Candidate Git workspace changed during verification')
            if (directory/'candidate.py').read_bytes()!=candidate.encode('utf-8'):
                raise PolicyError('Saved Blue candidate changed during verification')
            if (verify_snapshot(store,sid)['manifest_sha256'] != verified['manifest_sha256']):
                raise PolicyError('Source snapshot changed during verification')
            _, current_policy_hash=read_external_policy(store,sid,policy_path)
            if current_policy_hash!=policy_hash:
                raise PolicyError('Independent policy changed during verification')
            audit_progress()
            if _git(repo,'rev-parse','main')!=base_commit or _git(repo,'branch','--show-current')!=branch:
                raise PolicyError('Git baseline or work branch changed')
            _git(repo,'add','--',relative)
            _git(repo,'commit','-q','-m','SecurityLab: independently checked access policy fix')
            head=_git(repo,'rev-parse','HEAD')
            if head==base_commit or _git(repo,'status','--porcelain'):
                raise PolicyError('Isolated Git commit not clean or not distinct')
            output['git']={'directory':str(repo),'branch':branch,
                'base_commit':base_commit,'verified_commit':head,
                'diff':_git(repo,'diff','main..HEAD','--',relative),
                'source_repository_modified':False,'merged':False}
            output['status']='PASS'
            output['finding_status']='FIXED'
            output['security_verdict']='POLICY_VIOLATION_NOT_OBSERVED_ON_CHECKED_FIX'
    except KeyboardInterrupt:
        output.update(status='STOPPED',error='Stopped by operator')
    except (PolicyError,OSError,KeyError,ValueError,TypeError,IndexError) as exc:
        output.update(status='BLOCKED',error=str(exc)[:2000])
    finally:
        output['record']=str(directory/'summary.json')
        atomic_text(directory/'summary.json',json.dumps(output,ensure_ascii=False,indent=2))
    return output
