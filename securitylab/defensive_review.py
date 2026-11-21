"""Source review -> isolated patch -> operator functional regressions. No attack runner."""
import difflib
import json
import uuid
from pathlib import Path
from . import review_contract as contract, review_loop, app_map
from .access_ai import _observe, _sha, _jsonsha, _audit_ai_receipt, _prepare_git, _git
from .ai_config import AIConfig
from .hermes_adapter import HermesAdapter
from .http_runner import FastAPIHTTPDockerBroker
from .fastapi_probe import run_fastapi_http_observation
from .package_probe import _source_package
from .snapshots import _id, verify_snapshot
from .policy import Limits, PolicyError, safe_path
from .storage import atomic_text, worker_lock


def run_defensive_review(store,snapshot_id,entry,policy_path,*,service='.',execute=False,
        adapter_factory=HermesAdapter,broker_factory=FastAPIHTTPDockerBroker,
        observer=run_fastapi_http_observation,limits=Limits(),run_id=None,stop=None,progress=None):
    if execute is not True:raise PolicyError('Defensive runtime checks require explicit execute')
    sid=_id(snapshot_id);context,context_hash=contract.read_context(store,sid,policy_path)
    module,sources,package_hash,source_hash,verified=_source_package(store,sid,service,entry)
    relative='/'.join(entry.split('/')[0 if service=='.' else len(service.split('/')):])
    mapping=app_map.inventory(sources,relative);app_map.check_resources(mapping,context)
    plan=contract.regression_plan(context);plan_hash=_jsonsha(plan)
    identity=_id(run_id) if run_id else uuid.uuid4().hex
    folder=store.root/'access_ai'/identity;folder.mkdir(parents=True,exist_ok=False)
    emit=progress or (lambda *args:None)
    result=dict(schema_version=1,run_id=identity,mode='S10_DEFENSIVE_REVIEW',snapshot_id=sid,entry=entry,service=service,
        status='BLOCKED',finding_status=None,security_verdict='NOT_EVALUATED',context_sha256=context_hash,
        policy_sha256=plan_hash,manifest_sha256=verified['manifest_sha256'],package_sha256=package_hash,source_sha256=source_hash,
        scope='Defensive source review and operator GET functional regressions only; no vulnerability proof or automatic merge',
        checks_total=sum(len(p['checks']) for p in plan),stages={},ai_calls=[],candidates=[],application_map=mapping,
        regression_plan=plan,record=str(folder/'summary.json'))
    atomic_text(folder/'application_map.json',json.dumps(mapping,ensure_ascii=False,indent=2))
    atomic_text(folder/'functional_plan.json',json.dumps(plan,ensure_ascii=False,indent=2))
    atomic_text(folder/'original_package.json',json.dumps(sources,ensure_ascii=False,sort_keys=True))
    audits=[];candidate_audits=[]
    def checkpoint():
        if stop is not None and stop():raise PolicyError('Cancelled by operator')
    def audit():
        checkpoint()
        if verify_snapshot(store,sid)['manifest_sha256']!=verified['manifest_sha256'] or contract.read_context(store,sid,policy_path)[1]!=context_hash:raise PolicyError('Snapshot/operator rules changed')
        if json.loads((folder/'functional_plan.json').read_text('utf-8'))!=plan:raise PolicyError('Functional plan modified')
        for receipt,proposal,sha in audits:
            if _audit_ai_receipt(folder/'calls',receipt,proposal,ai_config)!=sha:raise PolicyError('AI receipt modified')
        for path,sha in candidate_audits:
            if _sha(path.read_bytes())!=sha:raise PolicyError('Saved candidate modified')
        if len({(s['image_id'],s['target_image_id']) for s in result['stages'].values()})>1:raise PolicyError('Runtime images changed')
        for name,stage in result['stages'].items():
            if stage['cleanup']!='PASS' or json.loads((folder/name/'summary.json').read_text('utf-8'))!=stage or _sha((folder/name/'docker_receipt.json').read_bytes())!=stage['receipt_sha256']:raise PolicyError('Functional evidence modified or cleanup failed')
    def batch(stage_name,files):
        matched=True
        for index,policy in enumerate(plan):
            audit();name=stage_name if index==0 else stage_name+'_'+str(index+1)
            emit(name,'running','Функциональные проверки: '+stage_name+f', пакет {index+1}/{len(plan)}')
            report=_observe(store,folder,identity,name,sid,service,entry,module,files,policy,_jsonsha(policy),verified['manifest_sha256'],broker_factory,observer,limits,stop,profile=contract.PROFILE)
            result['stages'][name]=report
            ok=report['status']=='ACCESS_POLICY_MATCHED';matched=matched and ok
            emit(name,'done' if ok else 'error','Функциональные проверки пройдены' if ok else 'Функциональные проверки не пройдены')
            audit()
        return matched
    (store.root/'ai').mkdir(exist_ok=True)
    try:
        with worker_lock(store.root/'ai'):
            checkpoint();ai_config=AIConfig()
            emit('map','done','Карта приложения построена без исполнения кода на хосте.')
            # Readiness and original regression baseline precede model calls.
            if not batch('baseline',sources):
                result.update(status='NEEDS_REVIEW',error='Исходное приложение не прошло функциональные проверки. Ревью и исправление не запускались.')
                return result
            adapter=adapter_factory(Path.cwd(),folder/'calls');ai_config=getattr(adapter,'config',AIConfig())
            result.update(ai_config=ai_config.data(),ai_config_sha256=ai_config.sha256)
            def ask(req):
                audit();proposal,receipt=adapter.ask(req,**({'stop':stop} if stop is not None else {}))
                contract.validate_reply(req,proposal)
                sha=_audit_ai_receipt(folder/'calls',receipt,proposal,ai_config)
                audits.append((receipt,proposal,sha))
                result['ai_calls'].append(dict(role=req['role'],id=receipt['id'],model_digest=ai_config.model_digest))
                return proposal,receipt
            review,_,history=review_loop.run(relative,sources,context,mapping,ask,folder,emit,checkpoint)
            result.update(review=review,review_history=history)
            if not review['review']:
                result.update(status='NEEDS_REVIEW',error='Агент не предложил обоснованных изменений. Безопасность не оценена.')
                return result
            emit('review','done','Замечания ревью получены; это предложения, не доказательства уязвимостей.')
            repo,branch,base=_prepare_git(folder,sources,relative,identity)
            files=dict(sources);feedback=None
            for number in (1,2):
                audit();emit('blue_'+str(number),'wait_model','Подготовка защитного исправления; ожидаем ответ.')
                req=contract.make_request('blue',relative,files,context,mapping,review=review['review'],retry=feedback)
                proposal,receipt=ask(req)
                if receipt.get('attempt') not in (1,2) or (number==2 and receipt['attempt']!=2):raise PolicyError('Invalid Blue attempt budget')
                patched=dict(files,**proposal['files'])
                # Patch remains within the supported runtime/route profile too.
                app_map.check_resources(app_map.inventory(patched,relative),context)
                encoded=json.dumps(patched,ensure_ascii=False,sort_keys=True)
                candidate_file=folder/f'candidate_{number}.json';atomic_text(candidate_file,encoded)
                candidate_audits.append((candidate_file,_sha(encoded)))
                changed=[p for p in sorted(sources) if patched[p]!=sources[p]]
                if not changed:raise PolicyError('No change relative to original snapshot')
                diff=''.join(line if line.endswith('\n') else line+'\n\\ No newline at end of file\n' for p in changed for line in difflib.unified_diff(sources[p].splitlines(keepends=True),patched[p].splitlines(keepends=True),fromfile='a/'+p,tofile='b/'+p))
                atomic_text(folder/f'candidate_{number}.patch',diff)
                result['candidates'].append(dict(file=candidate_file.name,sha256=_sha(encoded),changed_files=changed,call_id=receipt['id']))
                for p,source in patched.items():safe_path(repo,p).write_bytes(source.encode())
                _git(repo,'diff','--check')
                if set(_git(repo,'diff','--name-only').splitlines())!=set(changed):raise PolicyError('Unexpected patch paths')
                stage='candidate' if number==1 else 'candidate_retry'
                if batch(stage,patched):break
                if number==2 or receipt['attempt']==2:
                    result.update(status='NEEDS_REVIEW',error='Патч не прошёл функциональные регрессии; слияние не выполнялось.')
                    return result
                feedback=json.dumps({'functional_results':[{k:v for k,v in s.items() if k in ('stage','status','outcomes','observations')} for n,s in result['stages'].items() if n==stage or n.startswith(stage+'_')]},ensure_ascii=False)
                if len(feedback.encode())>16000:raise PolicyError('Regression feedback exceeds correction budget')
                files=patched
            if not batch('recheck',patched):
                result.update(status='NEEDS_REVIEW',error='Повторная функциональная проверка не подтвердила результат.')
                return result
            audit()
            if any(safe_path(repo,p).read_bytes()!=s.encode() for p,s in patched.items()) or _git(repo,'rev-parse','main')!=base or _git(repo,'branch','--show-current')!=branch:raise PolicyError('Isolated worktree changed')
            _git(repo,'add','--',*sorted(patched));_git(repo,'commit','-q','-m','SecurityLab defensive patch: operator functional checks passed')
            result['git']=dict(directory=str(repo),branch=branch,base_commit=base,verified_commit=_git(repo,'rev-parse','HEAD'),diff=_git(repo,'diff','main..HEAD','--',*sorted(patched)),source_repository_modified=False,merged=False)
            result.update(status='PASS',review_outcome='PATCH_PASSED_FUNCTIONAL_TESTS',cleanup='PASS')
            emit('commit','done','Патч сохранён отдельно. Функциональные проверки пройдены; безопасность не сертифицирована.')
    except (PolicyError,OSError,ValueError,TypeError,KeyError) as exc:
        result.update(status='BLOCKED',error=str(exc)[:2000])
        if stop is not None and stop():
            receipts=list((folder/'calls').glob('*.json'))+list(folder.glob('*/docker_receipt.json'))
            try:clean=all(json.loads(p.read_text('utf-8')).get('cleanup')=='PASS' for p in receipts)
            except (OSError,ValueError):clean=False
            result.update(status='STOPPED' if clean else 'BLOCKED',cleanup='PASS' if clean else 'FAIL')
    finally:
        atomic_text(folder/'summary.json',json.dumps(result,ensure_ascii=False,indent=2))
    return result
