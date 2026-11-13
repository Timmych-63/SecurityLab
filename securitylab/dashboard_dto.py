"""Read-model only: preserve execution, security verdict and finding separately."""
from datetime import datetime, timezone

def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()

def run_view(summary, identity, root, *, job=None, project_id='', modified=0):
    job = job or {}
    inp = job.get('input', {})
    status = summary.get('status', job.get('status', 'UNKNOWN'))
    states = {'PASS':'completed','DONE':'completed','BLOCKED':'blocked','NEEDS_REVIEW':'blocked',
              'STOPPED':'cancelled','TIMEOUT':'timeout','RUNNING':'running','QUEUED':'queued','INTERRUPTED':'blocked'}
    stages = summary.get('stages', {})
    checks = []
    base = stages.get('baseline', {}).get('observations', [])
    policy_checks = job.get('policy', {}).get('checks', [])
    for i, obs in enumerate(base):
        p = policy_checks[i] if i < len(policy_checks) else {}
        def probe(stage):
            rows = stages.get(stage, {}).get('observations', [])
            if i >= len(rows):
                return {'http':None,'outcome':'not_run'}
            a = rows[i]
            # HTTP equality alone is not a body-policy proof; retain raw report.
            return {'http':a.get('actual_status'), 'outcome':'pass' if a.get('passed') is True else 'fail',
                    'note':'HTTP observation; full policy result is in stage summary'}
        recheck = probe('recheck')
        checks.append(dict(id=p.get('id',str(i+1)),scenario=p.get('id',obs.get('path','')),
            group='anon' if obs.get('actor') is None else 'foreign' if obs.get('expected_status')==403 else 'regress',
            actor=obs.get('actor') or 'anonymous',method='GET',path=obs.get('path',''),expectStatus=obs.get('expected_status',0),
            baseline=probe('baseline'),candidate=probe('candidate'),candidateRetry=probe('candidate_retry'),recheck=recheck,
            final=('pass' if status=='PASS' and recheck['outcome']=='pass' else 'fail' if recheck['outcome']=='fail' else 'not_run')))
    cfg = summary.get('ai_config', job.get('ai_config', {}))
    git = summary.get('git', {})
    result = dict(id=identity,demo=False,projectId=inp.get('projectId',project_id),
        snapshotId=summary.get('snapshot_id',inp.get('snapshotId','')),service=summary.get('service',inp.get('service','.')),
        entryModule=summary.get('entry',inp.get('entryModule','')),profileId='access-ai-s72-v1',
        policyId=inp.get('policyId',summary.get('policy_sha256','')),aiConfigId=inp.get('aiConfigId','historical'),
        mode=summary.get('mode','S7_2_ACCESS_AI_SINGLE_MODULE'),stateDir=str(root),
        startedAt=iso(job.get('created',modified)),timingKnown=bool(job),timeLimitMin=cfg.get('timeout_seconds',1200)/60,
        exec=states.get(status,'failed'),status=status,error=summary.get('error',job.get('error')),
        security_verdict=summary.get('security_verdict','NOT_EVALUATED'),finding_status=summary.get('finding_status'),
        verdict=summary.get('security_verdict','NOT_EVALUATED'),finding=summary.get('finding_status'),
        stages=[dict(id=k,label=k,role='verifier',state='done',detail=v.get('status','')) for k,v in stages.items()],
        events=[dict(t=0,source='securitylab',text=summary.get('error') or job.get('error') or ('Status: '+status))],
        checks=checks,attempts=[],artifacts=[],aiConfiguration=cfg,
        tech=dict(image='securitylab-hermes:s4',imageDigest=next(iter(stages.values()),{}).get('image_id','нет данных'),
            network=cfg.get('network','нет данных'),configHash=summary.get('ai_config_sha256',job.get('ai_config_sha256','нет данных')),
            snapshotPin=summary.get('manifest_sha256','нет данных'),
            cleanup='нет данных; см. receipts',hashDisclaimer='Хеши — привязка сохранённых данных, не подпись.'))
    if job.get('finished'):
        result['finishedAt']=iso(job['finished'])
    elif summary:
        result['finishedAt']=iso(modified)
    if git.get('verified_commit'):
        result['commit']=dict(ref=git['branch'],sha=git['verified_commit'],isolated=True)
    if summary.get('red'):
        r=summary['red']
        result['redProposal']=dict(scenarioNo=r.get('check_id',''),summary=r.get('description',''),method='GET',path='',entry=r.get('file',''),aiGenerated=True)
    for i,c in enumerate(summary.get('candidates', [])):
        stage='candidate' if i==0 else 'candidate_retry'
        accepted=stages.get(stage,{}).get('status')=='ACCESS_POLICY_MATCHED'
        result['attempts'].append(dict(n=i+1,role=stage,status='accepted' if accepted else 'rejected',
            diff=git.get('diff',''),rejectionReasons=[] if accepted else ['See independent stage report'],checkSummary=stages.get(stage,{}).get('status','NOT_EVALUATED')))
    return result
