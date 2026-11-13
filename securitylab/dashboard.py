"""Local dashboard API over the existing SecurityLab core; no simulated runs."""
from __future__ import annotations
import argparse
import contextlib
import functools
import json
import mimetypes
import re
import secrets
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote
from .storage import Store
from .policy import PolicyError, Limits
from .projects import add_project, list_projects
from .snapshots import create_snapshot, list_snapshots
from .access_ai import run_access_ai, _source_package
from .access_baseline import read_external_policy
from .hermes_adapter import HermesAdapter
from .http_runner import FastAPIHTTPDockerBroker
from .dashboard_profiles import Profiles
from .dashboard_dto import run_view, iso
from .storage import atomic_text, worker_lock

ID = re.compile(r'[a-f0-9]{32}')
ROOT = Path(__file__).resolve().parents[1]

def bounded(path, base, limit=2*1024*1024):
    path, base = Path(path), Path(base).resolve()
    if not path.resolve().is_relative_to(base) or any(p.is_symlink() for p in [path, *path.parents] if p != base.parent):
        raise PolicyError('Unsafe artifact path')
    if not path.is_file() or path.stat().st_size > limit:
        raise PolicyError('Missing or oversized file')
    return path.read_bytes()

def read_json(path, base):
    return json.loads(bounded(path, base))

class Dashboard:
    def __init__(self, state, profiles, policies, runner=run_access_ai):
        self.root = Path(state).resolve()
        with contextlib.closing(Store(self.root)):
            pass
        self.jobs = self.root / 'dashboard_jobs'
        self.jobs.mkdir(exist_ok=True)
        self.profiles = Profiles(profiles)
        self.policies = Path(policies).resolve()
        self.runner = runner
        self.lock = threading.Lock()
        self.active = None
        self.grants = {}
        for path in self.jobs.glob('*.json'):
            value = read_json(path,self.root)
            if value.get('status') in ('QUEUED','RUNNING'):
                value.update(status='INTERRUPTED',error='Dashboard restarted; inspect saved receipts before retrying',finished=time.time())
                self.save_job(value)

    def save_job(self, job):
        atomic_text(self.jobs/(job['id']+'.json'),json.dumps(job,ensure_ascii=False,indent=2))

    def policy(self, identity):
        if not isinstance(identity,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',identity):
            raise PolicyError('Invalid policy ID')
        path=self.policies/(identity+'.json')
        return path,read_json(path,self.policies)

    def project_rows(self):
        with contextlib.closing(Store(self.root)) as store:
            rows=[]
            for p in list_projects(store):
                inventory=json.loads(store.db.execute('SELECT inventory_json FROM projects WHERE id=?',(p['id'],)).fetchone()[0])
                python_project=any(x.get('detected_profile')=='python' for x in inventory.get('services',[]))
                snaps=list_snapshots(store,p['id'])
                entries=[]
                # Entry candidates are listed without importing target code. Core admission remains mandatory.
                for snap in snaps:
                    manifest=read_json(self.root/'snapshots'/snap['id']/'manifest.json',self.root)
                    for item in manifest.get('files',[]):
                        name=item['path']
                        if name.endswith('.py') and name.rsplit('/',1)[-1] in ('main.py','app.py','service.py'):
                            e=dict(service='.',entryFile=name,entryImport=name)
                            if e not in entries: entries.append(e)
                rows.append(dict(id=p['id'],name=p['name'],path=p['source_path'],stack='Python / restricted FastAPI' if python_project else 'Unsupported stack',
                    profile='access-ai-s72-v1',supported=python_project,unsupportedReason=None if python_project else 'Only restricted Python/FastAPI access-ai is supported',services=entries,stateDir=str(self.root),
                    snapshots=[dict(id=s['id'],commit=s['id'][:12],createdAt=iso(s['created']),note='Content snapshot ID, not Git commit') for s in snaps]))
            return rows

    def validate_input(self, inp):
        keys={'projectId','snapshotId','service','entryModule','profileId','policyId','aiConfigId','stateDir'}
        if not isinstance(inp,dict) or set(inp)!=keys or not all(isinstance(v,str) for v in inp.values()):
            raise PolicyError('Invalid run input')
        if inp['stateDir']!=str(self.root) or inp['profileId']!='access-ai-s72-v1':
            raise PolicyError('State/profile must match this dashboard')
        if not ID.fullmatch(inp['projectId']) or not ID.fullmatch(inp['snapshotId']):
            raise PolicyError('Invalid project/snapshot')
        config=self.profiles.get(inp['aiConfigId'])
        policy_path,policy=self.policy(inp['policyId'])
        with contextlib.closing(Store(self.root)) as store:
            if not any(x['id']==inp['snapshotId'] for x in list_snapshots(store,inp['projectId'])):
                raise PolicyError('Snapshot does not belong to project')
            read_external_policy(store,inp['snapshotId'],policy_path)
            _source_package(store,inp['snapshotId'],inp['service'],inp['entryModule'])
        return config,policy_path,policy

    def probe_model(self, config):
        adapter=HermesAdapter(ROOT,self.root/'dashboard_probes',config=config)
        name='securitylab-check-'+uuid.uuid4().hex
        # Fixed trusted script, no target files, no shell, no generation; digest is checked by exact model name.
        script=('import json,urllib.request,sys; '
            'd=json.load(urllib.request.urlopen(sys.argv[1]+"/api/tags",timeout=5)); '
            'assert any(m.get("name")==sys.argv[2] and m.get("digest")==sys.argv[3] for m in d["models"]), "Model/digest mismatch"; print("MATCH")')
        try:
            adapter.call(['create','--name',name,'--network',config.network,'--read-only','--user','10001:10001',
                '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','--pids-limit','32','--cpus','0.5',
                '--entrypoint','python',adapter.image,'-c',script,config.server_url,config.model,config.model_digest],limits=Limits(timeout=10))
            result=adapter.call(['start','-a',name],limits=Limits(timeout=10))
            if result.stdout.strip()!='MATCH': raise PolicyError('Model check did not complete')
        finally:
            adapter.call(['rm','-f',name],limits=Limits(timeout=10))
        return {'ok':True,'detail':'Exact model name and digest match /api/tags. Generation and context capacity not tested.'}

    def preflight(self, inp):
        cfg,_,_=self.validate_input(inp)
        result=dict(docker='untested',images='untested',model='untested',params=inp,checkedAt=iso(time.time()))
        try:
            FastAPIHTTPDockerBroker(ROOT)
            result.update(docker='verified',images='verified',dockerDetail='Local Docker endpoint responds',imagesDetail='Demo and FastAPI image admission passed')
            self.probe_model(cfg)
            result.update(model='verified',modelDetail='Hermes image/network admitted; exact model name and digest found. Generation not tested.')
            with self.lock:
                if len(self.grants)>256: self.grants.clear()
                self.grants[json.dumps(inp,sort_keys=True)]=(time.monotonic(),cfg.sha256)
        except (PolicyError,OSError,ValueError) as exc:
            result['model']='error'
            result['modelDetail']=str(exc)
        return result

    def launch(self, inp):
        cfg,policy_path,policy=self.validate_input(inp)
        key=json.dumps(inp,sort_keys=True)
        with self.lock:
            grant=self.grants.get(key)
            if self.active: raise PolicyError('Another dashboard run is active')
            if not grant or time.monotonic()-grant[0]>120 or grant[1]!=cfg.sha256:
                raise PolicyError('Repeat preflight: configuration changed or readiness expired (120 seconds)')
            del self.grants[key]
            identity=uuid.uuid4().hex
            job=dict(id=identity,input=dict(inp),policy=policy,ai_config=cfg.data(),ai_config_sha256=cfg.sha256,
                     status='QUEUED',created=time.time())
            self.save_job(job)
            self.active=identity
            threading.Thread(target=self.work,args=(job,cfg,policy_path),daemon=False).start()
        return {'runId':identity}

    def work(self,job,cfg,policy_path):
        try:
            job['status']='RUNNING'; self.save_job(job)
            inp=job['input']
            with contextlib.closing(Store(self.root)) as store:
                # Explicit immutable object per run; never mutate process-global environment.
                result=self.runner(store,inp['snapshotId'],inp['entryModule'],policy_path,
                    service=inp['service'],execute=True,run_id=job['id'],
                    adapter_factory=functools.partial(HermesAdapter,config=cfg))
                job['status']=result['status']
        except Exception as exc:
            job.update(status='BLOCKED',error=str(exc)[:2000])
        finally:
            job['finished']=time.time(); self.save_job(job)
            with self.lock: self.active=None

    def run(self, identity):
        if not ID.fullmatch(identity): raise PolicyError('Invalid run ID')
        folder=self.root/'access_ai'/identity
        summary_path=folder/'summary.json'
        job_path=self.jobs/(identity+'.json')
        if not summary_path.exists() and not job_path.exists(): raise FileNotFoundError(identity)
        summary=read_json(summary_path,self.root) if summary_path.exists() else {}
        job=read_json(job_path,self.root) if job_path.exists() else {}
        project_id=''
        if summary.get('snapshot_id'):
            with contextlib.closing(Store(self.root)) as s:
                row=s.db.execute('SELECT project_id FROM project_snapshots WHERE id=?',(summary['snapshot_id'],)).fetchone()
                project_id=row['project_id'] if row else ''
        result=run_view(summary,identity,self.root,job=job,project_id=project_id,
                        modified=summary_path.stat().st_mtime if summary_path.exists() else job.get('created',0))
        # During a job expose completed independent stages already saved by core.
        if not summary:
            for name in ('baseline','candidate','candidate_retry','recheck'):
                path=folder/name/'summary.json'
                if path.exists():
                    v=read_json(path,self.root)
                    result['stages'].append(dict(id=name,label=name,role='verifier',state='done',detail=v.get('status','')))
        paths=[]
        if folder.exists():
            paths=[p for p in folder.rglob('*') if p.is_file() and '.git' not in p.parts and 'review_branch' not in p.parts and p.suffix in ('.json','.py','.log')]
        for i,path in enumerate(sorted(paths)[:200]):
            rel=path.relative_to(folder).as_posix()
            # IDs are relative paths; retrieval is restricted to this enumerated allowlist and bounded reads.
            result['artifacts'].append(dict(id=rel,name=rel,kind='json' if path.suffix=='.json' else 'text',present=True))
        if job:
            result['artifacts'].append(dict(id='dashboard-job',name='dashboard-job.json',kind='json',present=True))
        return result

    def dispatch(self, method, path, data=None, query=None):
        parts=path.strip('/').split('/')
        if method=='GET':
            if path=='/api/health': return dict(ok=True,mode='securitylab-core',scope='S7.2 single-module access AI',cancelSupported=False)
            if path=='/api/projects': return self.project_rows()
            if path=='/api/ai-configs': return self.profiles.list()
            if path=='/api/policies':
                result=[]
                for p in sorted(self.policies.glob('*.json'))[:100]:
                    _,v=self.policy(p.stem)
                    result.append(dict(id=p.stem,name=v.get('policy_id',p.stem),version=str(v.get('schema_version','')),
                        scope='External operator access policy',casesCount=len(v.get('checks',[])),subjects='Actor / record access',restrictions=['No auto-merge; independent Docker verification']))
                return result
            if path=='/api/diagnostics': return dict(available=False,note='Resource metrics not connected; no estimated CPU/GPU values.')
            if path=='/api/runs':
                ids={p.stem for p in self.jobs.glob('*.json')} | {p.parent.name for p in (self.root/'access_ai').glob('*/summary.json')}
                rows=[self.run(i) for i in ids if ID.fullmatch(i)]
                q=query or {}
                for key,field in [('projectId','projectId'),('status','exec'),('mode','mode')]:
                    value=q.get(key,['all'])[0]
                    if value!='all': rows=[r for r in rows if r.get(field)==value]
                return sorted(rows,key=lambda r:r['startedAt'],reverse=True)
            if len(parts)>=3 and parts[:2]==['api','runs']:
                r=self.run(parts[2])
                if len(parts)==3: return r
                folder=self.root/'access_ai'/parts[2]
                if len(parts)==4 and parts[3]=='patch':
                    summary=read_json(folder/'summary.json',self.root)
                    patch=summary.get('git',{}).get('diff')
                    if summary.get('status')!='PASS' or not patch: raise PolicyError('No independently verified patch available')
                    return dict(fileName=parts[2]+'.patch',content=patch)
                if len(parts)>=5 and parts[3]=='artifacts':
                    aid='/'.join(parts[4:])
                    artifact=next((a for a in r['artifacts'] if a['id']==aid),None)
                    if artifact is None: raise FileNotFoundError(aid)
                    p=self.jobs/(parts[2]+'.json') if aid=='dashboard-job' else folder/aid
                    return dict(artifact,content=bounded(p,self.root).decode('utf-8',errors='replace'))
        if method=='POST':
            if path=='/api/projects':
                if not isinstance(data,dict) or set(data)!={'path'} or not isinstance(data['path'],str): raise PolicyError('Expected project path')
                with contextlib.closing(Store(self.root)) as s: p=add_project(s,Path(data['path']))
                return next(r for r in self.project_rows() if r['id']==p['id'])
            if len(parts)==4 and parts[:2]==['api','projects'] and parts[3]=='snapshots':
                with contextlib.closing(Store(self.root)) as s: snap=create_snapshot(s,parts[2])
                return next(r for r in self.project_rows() if r['id']==parts[2])['snapshots'][-1]
            if len(parts)==4 and parts[:2]==['api','ai-configs']:
                cfg=self.profiles.get(parts[2])
                if parts[3]=='validate': return dict(valid=True,detail='Validated by ai_config.py; sha256 '+cfg.sha256)
                if parts[3]=='ping-model': return self.probe_model(cfg)
            if path=='/api/preflight': return self.preflight(data)
            if path=='/api/runs': return self.launch(data)
            if len(parts)==4 and parts[:2]==['api','runs'] and parts[3]=='cancel':
                raise PolicyError('Safe cancellation is not implemented for access-ai. This endpoint never reports a fake cancellation.')
        raise FileNotFoundError(path)

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def send(self,status,data,kind='application/json'):
        body=json.dumps(data,ensure_ascii=False).encode() if kind=='application/json' else data
        self.send_response(status)
        self.send_header('Content-Type',kind+'; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.end_headers(); self.wfile.write(body)
    def handle_request(self,method):
        try:
            host=self.headers.get('Host','')
            origin='http://'+host
            allowed={'127.0.0.1:'+str(self.server.server_port),'localhost:'+str(self.server.server_port)}
            if host not in allowed or self.headers.get('Sec-Fetch-Site')=='cross-site':
                return self.send(403,dict(ok=False,reason='Host/site denied'))
            if self.headers.get('Origin',origin)!=origin:
                return self.send(403,dict(ok=False,reason='Origin denied'))
            parsed=urlsplit(self.path); path=unquote(parsed.path)
            if method=='POST':
                if self.headers.get('Origin')!=origin or not secrets.compare_digest(self.headers.get('X-CSRF-Token',''),self.server.token):
                    return self.send(403,dict(ok=False,reason='CSRF denied'))
                length=int(self.headers.get('Content-Length','0'))
                if length<0 or length>16384: raise PolicyError('Request body exceeds limit')
                data=json.loads(self.rfile.read(length)) if length else None
            else: data=None
            if method=='GET' and path=='/api/csrf': return self.send(200,dict(token=self.server.token,expiresInMs=3600000))
            if path.startswith('/api/'):
                result=self.server.app.dispatch(method,path,data,parse_qs(parsed.query))
                return self.send(202 if method=='POST' and path=='/api/runs' else 200,result)
            if method!='GET': raise FileNotFoundError(path)
            if path=='/' or not Path(path).suffix:
                content=bounded(self.server.dist/'index.html',self.server.dist)
                content=content.replace(b'<head>',b'<head><meta name="securitylab-core" content="same-origin">')
                return self.send(200,content,'text/html')
            asset=self.server.dist/path.lstrip('/')
            return self.send(200,bounded(asset,self.server.dist,10*1024*1024),mimetypes.guess_type(str(asset))[0] or 'application/octet-stream')
        except FileNotFoundError: self.send(404,dict(ok=False,reason='Not found'))
        except (PolicyError,ValueError,KeyError,TypeError,OSError) as exc: self.send(400,dict(ok=False,reason=str(exc)[:1500]))
    def do_GET(self): self.handle_request('GET')
    def do_POST(self): self.handle_request('POST')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state',type=Path,required=True)
    p.add_argument('--profiles',type=Path,default=ROOT/'ai-profiles')
    p.add_argument('--policies',type=Path,default=ROOT/'examples'/'security_policies')
    p.add_argument('--dist',type=Path,default=ROOT/'dashboard'/'dist')
    p.add_argument('--port',type=int,default=8765)
    a=p.parse_args()
    if not (a.dist/'index.html').is_file(): p.error('Build dashboard first: cd dashboard; npm ci; npm run build')
    a.state.mkdir(parents=True,exist_ok=True)
    guard=a.state/'dashboard_jobs'; guard.mkdir(exist_ok=True)
    with worker_lock(guard):
        server=ThreadingHTTPServer(('127.0.0.1',a.port),Handler)
        server.app=Dashboard(a.state,a.profiles,a.policies)
        server.token=secrets.token_urlsafe(32); server.dist=a.dist.resolve()
        print(f'SecurityLab dashboard: http://127.0.0.1:{server.server_port}  state={server.app.root}',flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: print('Server stopped. An active run finishes with cleanup before process exit.',flush=True)
        finally:
            server.server_close()
            while server.app.active is not None:
                time.sleep(0.2)

if __name__=='__main__': main()
