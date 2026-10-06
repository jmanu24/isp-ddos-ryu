from __future__ import annotations
import asyncio
import contextlib
import copy
import io
import json
import os
import re
import secrets
import shutil
import uuid
import time
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Literal
from .config import ROOT, load_lab, resolve, mapping_issues
from .ground_truth import windows
from .planner import DOMAINS, canonical, generate, generate_benchmark, load_profiles, save_plan, validate
from .runner import Manager, TERMINAL, csv_text
from .interface_monitor import InterfaceMonitor
from .host_monitor import HostMonitor
from .vm_resources import VmResourceMonitor
from .detection_audit import DetectionAuditMonitor
from .detection_evaluation import evaluate as evaluate_detection, calibration as replay_calibration
from .threshold_control import ThresholdControl
from .experiment_jobs import ExperimentJobs
from .experimental_analytics import ExperimentalAnalytics, csv_data as analytics_csv


class PlanRequest(BaseModel):
    seed: int = 1
    duration_s: float = Field(default=600, ge=5, le=3600)
    capacity_mbps: Optional[Dict[str,float]] = None
    benchmark_domain: Optional[Literal['mobile','fixed','enterprise','peering']] = None

class AttackWindow(BaseModel):
    name: str = Field(min_length=1,max_length=80)
    start_s: float = Field(ge=0,allow_inf_nan=False)
    end_s: float = Field(gt=0,allow_inf_nan=False)

class RunRequest(BaseModel):
    plan_hash: str
    mode: str = 'simulation'
    scenario: str = 'B0'
    pipeline: str = 'enabled'
    execution_profile: Optional[Literal['classic','coordinated','persistent']] = None
    speed: float = Field(default=20,ge=.1,le=100)
    attack_windows: List[AttackWindow] = Field(default_factory=list,max_length=100)

class JobRequest(BaseModel):
    run: RunRequest
    count: int = Field(default=1, ge=1, le=100)
    gap_s: float = Field(default=0, ge=0, le=86400, allow_inf_nan=False)
    scheduled_at: Optional[float] = Field(default=None, allow_inf_nan=False)


class BatchDeleteRequest(BaseModel):
    run_ids: List[str] = Field(default_factory=list,max_length=1000)
    plan_hashes: List[str] = Field(default_factory=list,max_length=1000)
    seeds: List[int] = Field(default_factory=list,max_length=1000)
    dry_run: bool = True


class Annotation(BaseModel):
    name: str = Field(default='external_attack',min_length=1,max_length=80)
    action: str


def create_app(data_dir=None,lab_path=None,profiles_path=None,token=None):
    data=Path(data_dir or os.getenv('BENIGN_DATA',ROOT/'data')).resolve()
    lab_path=Path(lab_path or os.getenv('BENIGN_LAB_CONFIG',ROOT/'config/lab.demo.yaml')).resolve()
    profiles_path=Path(profiles_path or os.getenv('BENIGN_PROFILES',ROOT/'profiles')).resolve()
    token=token if token is not None else os.getenv('BENIGN_API_TOKEN','')
    plans=data/'plans'
    plans.mkdir(parents=True,exist_ok=True)
    manager=Manager(data/'runs')
    analytics=ExperimentalAnalytics(data,manager)
    interfaces=InterfaceMonitor(data/'traffic',load_lab(lab_path))
    hosts=HostMonitor(data/'resources',load_lab(lab_path))
    guests=VmResourceMonitor(data/'vm_resources',load_lab(lab_path))
    interfaces.resources=guests
    guest_cursors={}
    def capture_guests(rid):
        r=manager.runs[rid]
        if r['mode']!='lab':return
        path=manager.folder(rid)/'vm_resources.jsonl'
        if rid not in guest_cursors:
            guest_cursors[rid]=max((json.loads(l)['id'] for l in path.read_text().splitlines()),default=0) if path.exists() else 0
        rows=guests.rows(r.get('started_at') or r['created_at'],r.get('finished_at') or time.time(),guest_cursors[rid])
        if rows:
            with path.open('a') as f:
                for row in rows:f.write(json.dumps(row)+'\n')
            guest_cursors[rid]=rows[-1]['id']
    host_cursors={}
    def capture_hosts(rid):
        r=manager.runs[rid]
        if r['mode']!='lab':return
        path=manager.folder(rid)/'host_metrics.jsonl'
        if rid not in host_cursors:
            host_cursors[rid]=max((json.loads(l)['id'] for l in path.read_text().splitlines()),default=0) if path.exists() else 0
        rows=hosts.rows(r.get('started_at') or r['created_at'],r.get('finished_at') or time.time(),host_cursors[rid])
        if rows:
            with path.open('a') as f:
                for row in rows:f.write(json.dumps(row)+'\n')
            host_cursors[rid]=rows[-1]['id']
    previous={}
    interface_cursors={}
    def capture_interfaces(rid):
        r=manager.runs[rid]
        if r['mode']!='lab': return []
        path=manager.folder(rid)/'interface_metrics.jsonl'
        if rid not in interface_cursors:
            interface_cursors[rid]=max((json.loads(line)['id'] for line in path.read_text().splitlines()),default=0) if path.exists() else 0
        rows=interfaces.rows(r.get('started_at') or r['created_at'],r.get('finished_at') or time.time(),interface_cursors[rid])
        if rows:
            with path.open('a') as f:
                for row in rows:f.write(json.dumps(row)+'\n')
            interface_cursors[rid]=rows[-1]['id']
        return rows
    audit=DetectionAuditMonitor(data,load_lab(lab_path))
    audit_cursors={}
    def capture_audit(rid):
        r=manager.runs[rid]
        if r['mode']!='lab':return
        path=manager.folder(rid)/'detection_events.jsonl'
        if rid not in audit_cursors:
            audit_cursors[rid]=max((json.loads(line)['id'] for line in path.read_text().splitlines()),default=0) if path.exists() else 0
        rows=audit.rows(r.get('started_at') or r['created_at'],r.get('finished_at') or time.time(),audit_cursors[rid])
        if rows:
            with path.open('a') as f:
                for row in rows:f.write(json.dumps(row)+'\n')
            audit_cursors[rid]=rows[-1]['id']
        (manager.folder(rid)/'audit_capture_status.json').write_text(json.dumps(audit.status))
    def evaluation_dataset(rid):
        r=copy.deepcopy(manager.runs[rid]);r['elapsed_s']=manager.elapsed(rid);folder=manager.folder(rid)
        def read_lines(name):
            path=folder/name
            return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []
        r['_lab']=json.loads((folder/'lab_snapshot.json').read_text()) if (folder/'lab_snapshot.json').exists() else {}
        return (read_plan(r['plan_hash']),r,read_lines('detection_events.jsonl'),read_lines('interface_metrics.jsonl'),[dict(e) for e in manager.events.get(rid,{}).values()])
    def evaluation_for(rid):
        try:value=evaluate_detection(*evaluation_dataset(rid))
        except (FileNotFoundError,KeyError):value=dict(schema=1,available=False,domains=[],windows=[],ip_changes=[],impact=[],threshold_snapshots=[],decision_weights=None,limitations=['Historical export lacks complete plan or evidence; no FP/TN inferred'])
        value['capture_status']=dict(audit.status)
        folder=manager.folder(rid)
        atomic_payload=json.dumps(value,indent=2);tmp=folder/'detection_evaluation.tmp';tmp.write_text(atomic_payload);tmp.replace(folder/'detection_evaluation.json')
        (folder/'detection_windows.csv').write_text(csv_text(value['windows']))
        (folder/'threshold_snapshot.json').write_text(json.dumps(dict(policies=value['threshold_snapshots'],weights=value['decision_weights']),indent=2))
        (folder/'fixed_ip_changes.json').write_text(json.dumps(value['ip_changes'],indent=2))
        return value
    control_lock=None
    def control_change_lock():
        nonlocal control_lock
        if control_lock is None:control_lock=asyncio.Lock()
        return control_lock
    capture_locks={}
    async def background(fn):
        future=asyncio.get_running_loop().run_in_executor(None,fn)
        try:return await asyncio.shield(future)
        except asyncio.CancelledError:
            await future
            raise
    def capture_lock(rid):
        return capture_locks.setdefault(rid,asyncio.Lock())
    def capture_sync(rid):
        capture_interfaces(rid);capture_hosts(rid);capture_guests(rid);capture_audit(rid)
    async def capture_run(rid):
        async with capture_lock(rid):
            if rid in manager.runs: await background(lambda:capture_sync(rid))
    async def history_response(rid,filename,after,metadata):
        async with capture_lock(rid):
            def work():
                capture_sync(rid)
                path=manager.folder(rid)/filename
                rows=[json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
                return JSONResponse(dict(items=[row for row in rows if row['id']>after],cursor=max((row['id'] for row in rows),default=after),historical=True,available=bool(rows),**metadata))
            return await background(work)
    finalized=set(manager.runs)
    async def monitor():
        tick=0
        while True:
            await asyncio.sleep(1)
            tick+=1
            for rid,r in list(manager.runs.items()):
                if r['status'] in TERMINAL and rid in finalized: continue
                await capture_run(rid)
                if rid not in manager.runs: continue
                if r['status'] in TERMINAL:
                    if r.get('finished_at'): finalized.add(rid)
                    continue
                snap=manager.snapshot(rid)
                now=time.monotonic()
                total=snap['bytes_tx']+snap['bytes_rx']
                before=previous.get(rid,(now,total))
                bps=max(0,total-before[1])*8/max(.001,now-before[0])
                if r['mode']=='simulation': bps/=r['speed']
                previous[rid]=(now,total)
                r['payload_mbps']=bps/1e6
                row=dict(timestamp=time.time(),elapsed_s=snap['elapsed_s'],bytes_tx=snap['bytes_tx'],bytes_rx=snap['bytes_rx'],
                         payload_mbps=r['payload_mbps'],active_planned_mbps=snap['active_planned_mbps'],metrics_kind=r['metrics_kind'],domains=snap['domains'])
                with (manager.folder(rid)/'metrics.jsonl').open('a') as f: f.write(json.dumps(row)+'\n')
                if tick%5==0: await manager.persist_async(rid)
    @asynccontextmanager
    async def lifespan(app):
        interfaces.start()
        hosts.start()
        guests.start()
        audit.start()
        task=asyncio.create_task(monitor())
        jobs.launch()
        yield
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError): await task
        await jobs.shutdown()
        await manager.shutdown()
        await interfaces.stop()
        await hosts.stop()
        await guests.stop()
        await audit.stop()
    app=FastAPI(title='DDOS PUCP LAB',version='1.0.0',lifespan=lifespan)
    app.state.manager=manager
    app.state.interface_monitor=interfaces
    app.state.host_monitor=hosts
    app.state.vm_resources=guests
    app.state.detection_audit=audit
    @app.get('/api/vm-resources')
    async def vm_resources(minutes:int=5,after:int=0):
        return await asyncio.get_running_loop().run_in_executor(None,lambda: JSONResponse(guests.response(max(1,min(minutes,360)),max(0,after))))
    @app.get('/api/runs/{rid}/vm-resources')
    async def run_vm_resources(rid:str,after:int=0):
        run_for(rid)
        return await history_response(rid,'vm_resources.jsonl',after,dict(hosts=[]))
    @app.get('/api/resources')
    async def resources(minutes:int=5,after:int=0):
        return await asyncio.get_running_loop().run_in_executor(None,lambda: JSONResponse(hosts.response(max(1,min(minutes,360)),max(0,after))))
    @app.get('/api/runs/{rid}/resources')
    async def run_resources(rid:str,after:int=0):
        run_for(rid)
        return await history_response(rid,'host_metrics.jsonl',after,dict(hosts=[]))
    @app.get('/api/traffic')
    async def traffic(minutes:int=5,after:int=0):
        return await asyncio.get_running_loop().run_in_executor(None,lambda: JSONResponse(interfaces.response(max(1,min(minutes,360)),max(0,after))))
    @app.get('/api/runs/{rid}/interface-traffic')
    async def interface_traffic(rid:str,after:int=0):
        run_for(rid)
        return await history_response(rid,'interface_metrics.jsonl',after,dict(metrics_kind='linux_interface_counters',nodes=[],interval_s=5))
    @app.middleware('http')
    async def guard(request,call_next):
        if request.url.path.startswith('/api'):
            host=request.headers.get('host','')
            trusted=set(os.getenv('BENIGN_ALLOWED_HOSTS','localhost,127.0.0.1,::1,testserver').split(','))
            if urlparse('http://'+host).hostname not in trusted:
                return JSONResponse({'detail':'Host is not allowed; configure BENIGN_ALLOWED_HOSTS'},400)
            origin=request.headers.get('origin')
            if origin and urlparse(origin).netloc!=host:
                return JSONResponse({'detail':'Cross-origin API request refused'},403)
            if token and not secrets.compare_digest(request.headers.get('authorization',''),'Bearer '+token):
                return JSONResponse({'detail':'API token required'},401)
            length=request.headers.get('content-length')
            if length and int(length)>32*1024*1024:
                return JSONResponse({'detail':'Payload limit: 32 MiB'},413)
        response=await call_next(request)
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='same-origin'
        return response
    @app.exception_handler(ValueError)
    async def invalid(request,exc): return JSONResponse({'detail':str(exc)},400)
    def path_for(ph):
        if not re.fullmatch(r'[0-9a-f]{64}',ph): raise HTTPException(400,'Invalid plan hash')
        path=plans/f'{ph}.json'
        if not path.exists(): raise HTTPException(404,'Plan not found')
        return path
    plan_cache={}
    def readable_plan_path(ph):
        try: path=path_for(ph)
        except HTTPException as exc:
            if exc.status_code != 404: raise
            path=next((manager.folder(rid)/'benign_plan.json' for rid,r in manager.runs.items() if r['plan_hash']==ph and (manager.folder(rid)/'benign_plan.json').exists()), None)
            if path is None: raise
        return path
    def read_plan(ph):
        path=readable_plan_path(ph)
        stat=path.stat()
        signature=(stat.st_mtime_ns,stat.st_size)
        cached=plan_cache.get(ph)
        if cached is None or cached[0]!=signature:
            cached=(signature,validate(json.loads(path.read_text())))
            plan_cache[ph]=cached
        return cached[1]
    def run_for(rid):
        if rid not in manager.runs: raise HTTPException(404,'Experiment not found')
        return manager.runs[rid]
    @app.get('/api/config')
    def config():
        lab=load_lab(lab_path)
        return dict(lab=lab,lab_path=str(lab_path),mapping_issues=mapping_issues(lab),profiles=load_profiles(profiles_path),capabilities=['simulation','local','netns','ssh','ssh_netns'])
    @app.get('/api/plans')
    def list_plans():
        rows=[]
        for f in plans.glob('*.json'):
            p=json.loads(f.read_text())
            rows.append({**{k:p[k] for k in ('plan_hash','seed','duration_s','summary','warnings','capacity_mbps')},'purpose':p.get('purpose'),'benchmark_domain':p.get('benchmark_domain')})
        return rows[::-1]
    @app.post('/api/plans')
    def make_plan(body:PlanRequest):
        capacities=body.capacity_mbps or load_lab(lab_path)['capacity_mbps']
        p=generate_benchmark(load_profiles(profiles_path),body.seed,body.duration_s,capacities,body.benchmark_domain) if body.benchmark_domain else generate(load_profiles(profiles_path),body.seed,body.duration_s,capacities)
        save_plan(p,plans/f'{p["plan_hash"]}.json')
        return p
    @app.post('/api/plans/import')
    async def import_plan(request:Request):
        raw=await request.body()
        if len(raw)>32*1024*1024: raise HTTPException(413,'Payload too large')
        try:
            p=json.loads(raw)
            validate(p)
        except (ValueError,KeyError,TypeError,OverflowError) as exc:
            raise HTTPException(400,f'Invalid plan: {exc}') from exc
        # Preserve the bytes of an imported plan for all paired runs.
        path=plans/f'{p["plan_hash"]}.json'
        if not path.exists(): path.write_bytes(raw)
        return p
    @app.get('/api/plans/{ph}')
    def get_plan(ph:str): return read_plan(ph)
    @app.get('/api/plans/{ph}/download')
    def download_plan(ph:str): return FileResponse(readable_plan_path(ph),filename='benign_plan.json',media_type='application/json')
    @app.post('/api/plans/{ph}/preflight')
    def preflight(ph:str):
        groups=resolve(load_lab(lab_path),read_plan(ph))
        return dict(ok=True,scope='configuration_only; connectivity checked on lab start',groups=[dict(sources=sorted(g['sources']),events=len(g['events']),command=g['argv'],context=g['context']) for g in groups.values()])
    @app.get('/api/runs')
    async def list_runs():
        result=[]
        for rid in reversed(manager.runs):
            value=manager.snapshot(rid);path=manager.folder(rid)/'detection_events.jsonl';value['audit_available']=path.exists() and path.stat().st_size>0;result.append(value)
        return result
    @app.post('/api/runs')
    async def start_run(body:RunRequest):
        async with control_change_lock():
            if jobs.active(): raise ValueError('Ya hay una prueba activa; utilice una serie para esperar su finalización')
            return await launch_request(body.model_dump())
    async def launch_request(raw):
        body=RunRequest(**raw)
        p=read_plan(body.plan_hash)
        return await manager.start(p,path_for(body.plan_hash),load_lab(lab_path),body.mode,body.scenario,body.speed,[w.model_dump() for w in body.attack_windows],body.pipeline,body.execution_profile)
    jobs=ExperimentJobs(data,manager,control_change_lock,launch_request,path_for)
    app.state.experiment_jobs=jobs
    @app.get('/api/jobs')
    async def list_jobs(): return list(reversed(list(jobs.jobs.values())))
    @app.post('/api/jobs')
    async def create_job(body:JobRequest):
        if body.run.scenario!='B0' or body.run.attack_windows:
            raise HTTPException(400,'Las series automáticas admiten B0; los ataques externos requieren ejecución y anotación manual')
        if body.run.mode not in ('lab','simulation') or body.run.pipeline not in ('baseline','enabled'):
            raise HTTPException(400,'Modo o pipeline inválido')
        p=read_plan(body.run.plan_hash)
        if p.get('purpose')=='domain_benchmark' and body.run.mode=='lab' and body.run.pipeline!='baseline':
            raise HTTPException(400,'Benchmark de laboratorio requiere pipeline baseline')
        async with control_change_lock():
            return jobs.create(body.run.model_dump(),body.count,body.gap_s,body.scheduled_at)
    @app.post('/api/jobs/{jid}/cancel')
    async def cancel_job(jid:str):
        async with control_change_lock(): return jobs.cancel(jid)
    def trash(source,kind):
        target=data/'trash'/kind/(str(int(time.time()))+'-'+uuid.uuid4().hex+'-'+source.name)
        target.parent.mkdir(parents=True,exist_ok=True)
        source.rename(target)
        return dict(deleted=True,recoverable=True,trash_id=target.name)
    @app.delete('/api/plans/{ph}')
    async def delete_plan(ph:str):
        async with control_change_lock():
            if jobs.references(ph) or any(r['plan_hash']==ph and r['status'] not in TERMINAL for r in manager.runs.values()):
                raise HTTPException(409,'Plan utilizado por una prueba activa o una serie pendiente')
            result=trash(path_for(ph),'plans')
            plan_cache.pop(ph,None)
            return result
    @app.delete('/api/seeds/{seed}')
    async def delete_seed(seed:int):
        async with control_change_lock():
            files=[f for f in plans.glob('*.json') if json.loads(f.read_text())['seed']==seed]
            if not files: raise HTTPException(404,'Semilla no encontrada')
            hashes=[f.stem for f in files]
            if any(jobs.references(ph) for ph in hashes) or any(r['plan_hash'] in hashes and r['status'] not in TERMINAL for r in manager.runs.values()):
                raise HTTPException(409,'Semilla utilizada por una prueba activa o serie pendiente')
            result=[trash(f,'plans') for f in files]
            for ph in hashes: plan_cache.pop(ph,None)
            return dict(deleted=len(result),recoverable=True)
    @app.delete('/api/runs/{rid}')
    async def delete_run(rid:str):
        async with control_change_lock():
            if jobs.active(): raise HTTPException(409,'Espere que termine la prueba activa antes de borrar evidencia')
            async with capture_lock(rid):
                with analytics.lock:
                    folder=analytics.folders().get(rid)
                    if folder is None: raise HTTPException(404,'Prueba no encontrada')
                    r=manager.runs.get(rid) or json.loads((folder/'run.json').read_text())
                    if r['status'] not in TERMINAL: raise HTTPException(409,'La prueba todavía está activa')
                    if rid in manager.tasks and not manager.tasks[rid].done(): raise HTTPException(409,'La prueba todavía está cerrando sus agentes')
                    result=trash(folder,'runs')
                    for name in ('runs','tasks','stops','processes','supervisors','events','logs','origins','plan_cache','terminal_metrics'):
                        getattr(manager,name,{}).pop(rid,None)
                    analytics.cache.pop(rid,None);analytics.detail_cache.pop(rid,None)
                    return result
    @app.post('/api/lifecycle/batch-delete')
    async def batch_delete(body:BatchDeleteRequest):
        hashes=set(body.plan_hashes)
        for f in plans.glob('*.json'):
            if json.loads(f.read_text())['seed'] in body.seeds: hashes.add(f.stem)
        if len(hashes)>2000: raise HTTPException(400,'Máximo 2000 planes por lote')
        targets=[('run',rid) for rid in dict.fromkeys(body.run_ids)]+[('plan',ph) for ph in sorted(hashes)]
        if not targets: raise HTTPException(400,'Seleccione al menos una prueba o plan')
        result=[]
        for kind,identifier in targets:
            row=dict(kind=kind,id=identifier)
            try:
                if body.dry_run:
                    if kind=='run':
                        folder=analytics.folders().get(identifier)
                        if folder is None: raise HTTPException(404,'Prueba no encontrada')
                        r=manager.runs.get(identifier) or json.loads((folder/'run.json').read_text())
                        if jobs.active() or r['status'] not in TERMINAL: raise HTTPException(409,'Hay una prueba activa; espere a su finalización')
                    else:
                        path_for(identifier)
                        if jobs.references(identifier) or any(r['plan_hash']==identifier and r['status'] not in TERMINAL for r in manager.runs.values()):
                            raise HTTPException(409,'Plan utilizado por una prueba activa o serie pendiente')
                    row['status']='ready'
                else:
                    value=await (delete_run(identifier) if kind=='run' else delete_plan(identifier))
                    row.update(status='deleted',trash_id=value['trash_id'])
            except HTTPException as exc:row.update(status='blocked' if exc.status_code==409 else 'error',detail=exc.detail)
            result.append(row)
        return dict(dry_run=body.dry_run,items=result,counts={key:sum(r['status']==key for r in result) for key in ('ready','deleted','blocked','error')},recoverable=True)
    @app.get('/api/runs/{rid}')
    async def get_run(rid:str):
        run_for(rid)
        return manager.snapshot(rid)
    @app.post('/api/runs/{rid}/stop')
    async def stop_run(rid:str):
        run_for(rid)
        return await manager.stop(rid)
    @app.post('/api/runs/{rid}/attack')
    async def annotate(rid:str,body:Annotation):
        run_for(rid)
        result=manager.annotate(rid,body.name,body.action)
        await manager.persist_async(rid)
        return result
    @app.get('/api/runs/{rid}/events')
    async def events(rid:str,domain:str='',status:str='',offset:int=0,limit:int=100):
        run_for(rid)
        es=[e for e in manager.events[rid].values() if (not domain or e['domain']==domain) and (not status or e['status']==status)]
        offset=max(0,offset)
        return dict(total=len(es),items=es[offset:offset+max(1,min(limit,500))])
    @app.get('/api/runs/{rid}/ground-truth')
    async def truth(rid:str):
        r=run_for(rid)
        return windows(read_plan(r['plan_hash']),manager.snapshot(rid))
    @app.get('/api/runs/{rid}/stream')
    async def stream(rid:str,request:Request):
        run_for(rid)
        async def output():
            while not await request.is_disconnected():
                snap=manager.snapshot(rid)
                yield 'data: '+json.dumps(snap)+'\n\n'
                if snap['status'] in TERMINAL: break
                await asyncio.sleep(.5)
        return StreamingResponse(output(),media_type='text/event-stream',headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})
    @app.get('/api/runs/{rid}/export')
    async def export(rid:str):
        benchmark_export=run_for(rid).get('purpose')=='domain_benchmark'
        def build_zip():
            evaluation_for(rid)
            buffer=io.BytesIO()
            with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as z:
                for f in manager.folder(rid).iterdir():
                    if f.suffix in ('.json','.jsonl','.csv') or f.name=='failure_traceback.txt':z.write(f,f.name)
                if benchmark_export:
                    stored=json.loads((manager.folder(rid)/'run.json').read_text())
                    events=json.loads((manager.folder(rid)/'event_states.json').read_text()).values()
                    actual=sum(e['bytes_tx']+e['bytes_rx'] for e in events);planned=stored['benchmark_planned_bytes']
                    summary=dict(domain=stored['benchmark_domain'],plan_hash=stored['plan_hash'],execution_hash=stored['execution_hash'],status=stored['status'],elapsed_s=stored['elapsed_s'],planned_bytes=planned,actual_bytes=actual,observed_pct=100*actual/planned,planned_mean_mbps=planned*8/stored['duration_s']/1e6,observed_mean_mbps=actual*8/max(stored['elapsed_s'],.001)/1e6,failed_events=sum(e['status']=='failed' for e in events),metrics_kind=stored['metrics_kind'])
                    z.writestr('benchmark_summary.json',json.dumps(summary,indent=2))
            return buffer.getvalue()
        async with capture_lock(rid):
            await background(lambda:capture_sync(rid))
            content=await manager.persist_async(rid,after=build_zip)
        return Response(content,media_type='application/zip',headers={'Content-Disposition':f'attachment; filename="{rid}.zip"'})
    @app.get('/api/detection-audit/status')
    async def audit_status():return dict(audit.status)
    @app.get('/api/runs/{rid}/detection-evaluation')
    async def detection_evaluation(rid:str):
        run_for(rid)
        async with capture_lock(rid):
            return await background(lambda:(capture_sync(rid),evaluation_for(rid))[1])
    @app.get('/api/calibration/thresholds')
    async def threshold_values():
        try:return await ThresholdControl(load_lab(lab_path)).read()
        except (RuntimeError,ValueError,KeyError) as exc:raise HTTPException(503,'Threshold configuration unavailable: '+str(exc)) from exc
    @app.post('/api/calibration/thresholds')
    async def update_thresholds(request:Request):
        body=await request.json()
        if not isinstance(body,dict) or not isinstance(body.get('values'),dict) or not isinstance(body.get('expected_hash'),str):raise HTTPException(400,'Invalid threshold update')
        async with control_change_lock():
            if any(r['status'] not in TERMINAL for r in manager.runs.values()):raise HTTPException(409,'Wait until all experiments finish')
            try:return await ThresholdControl(load_lab(lab_path)).apply(body['values'],body['expected_hash'])
            except (ValueError,RuntimeError) as exc:raise HTTPException(400,str(exc)) from exc
    @app.get('/api/calibration/download')
    async def calibration_download():
        path=data/'calibration_last.json'
        if not path.exists():raise HTTPException(404,'No calibration result')
        return FileResponse(path,filename='threshold_calibration.json',media_type='application/json')
    @app.post('/api/calibration/replay')
    async def replay_thresholds(request:Request):
        body=await request.json()
        if not isinstance(body,dict):raise HTTPException(400,'Invalid replay selection')
        train=body.get('training_ids',[]);valid=body.get('validation_ids',[]);thresholds=body.get('thresholds',[])
        if not isinstance(train,list) or not isinstance(valid,list) or not isinstance(thresholds,list) or len(train)+len(valid)>40 or not 1<=len(thresholds)<=30:raise HTTPException(400,'Invalid replay selection')
        if any(not isinstance(rid,str) for rid in train+valid) or len(set(train))!=len(train) or len(set(valid))!=len(valid) or any(isinstance(t,bool) or not isinstance(t,(int,float)) for t in thresholds):raise HTTPException(400,'Invalid replay values')
        datasets={}
        for rid in train+valid:
            run_for(rid)
            async with capture_lock(rid):datasets[rid]=await background(lambda rid=rid:(capture_sync(rid),evaluation_dataset(rid))[1])
        try:
            result=await background(lambda:replay_calibration(datasets,train,valid,thresholds))
            result['generated_at']=time.time();(data/'calibration_last.json').write_text(json.dumps(result,indent=2));return result
        except (ValueError,TypeError) as exc:raise HTTPException(400,str(exc)) from exc
    def analytics_idle():
        if any(r['status'] not in TERMINAL for r in manager.runs.values()):raise HTTPException(409,'El análisis detallado estará disponible cuando finalice la prueba activa; se protege la adquisición experimental.')
    @app.get('/api/analytics/catalog')
    async def analytics_catalog():return await background(analytics.catalog)
    @app.get('/api/analytics/runs/{rid}')
    async def analytics_detail(rid:str,domain:str='all'):
        analytics_idle()
        try:return await background(lambda:analytics.detail(rid,domain))
        except ValueError as exc:raise HTTPException(400,str(exc)) from exc
    @app.post('/api/analytics/report')
    async def analytics_report(request:Request):
        analytics_idle()
        body=await request.json()
        if not isinstance(body,dict) or not isinstance(body.get('run_ids'),list):raise HTTPException(400,'Select executions')
        if not isinstance(body.get('precision',1),(int,float)) or isinstance(body.get('precision',1),bool) or not 0<body.get('precision',1)<=1000000:raise HTTPException(400,'Invalid precision')
        try:return await background(lambda:analytics.report(body['run_ids'],body.get('domain','all'),body.get('metric','delivery_pct'),body.get('precision',1)))
        except ValueError as exc:raise HTTPException(400,str(exc)) from exc
    @app.post('/api/analytics/export')
    async def analytics_export(request:Request):
        analytics_idle()
        body=await request.json()
        if not isinstance(body,dict) or not isinstance(body.get('run_ids'),list):raise HTTPException(400,'Select executions')
        if not isinstance(body.get('precision',1),(int,float)) or isinstance(body.get('precision',1),bool) or not 0<body.get('precision',1)<=1000000:raise HTTPException(400,'Invalid precision')
        try:report=await background(lambda:analytics.report(body['run_ids'],body.get('domain','all'),body.get('metric','delivery_pct'),body.get('precision',1)))
        except ValueError as exc:raise HTTPException(400,str(exc)) from exc
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('experimental_report.json',json.dumps(report,indent=2))
            archive.writestr('execution_comparison.csv',analytics_csv(report))
            summaries=[]
            for group in report['groups']:
                stats=group['statistics'];ci=stats['ci95'];summaries.append(dict(group_id=group['group_id'],domain=report['domain'],metric=report['metric'],n_runs=stats['n_runs'],n_seeds=stats['n_seeds'],seed_balanced_mean=stats['seed_balanced']['mean'],sd_between_seeds=stats['seed_balanced']['sd'],ci95_low=ci['low'] if ci else None,ci95_high=ci['high'] if ci else None,ci_unavailable_reason=stats['ci_unavailable_reason']))
            archive.writestr('cohort_statistics.csv',csv_text(summaries))
            archive.writestr('METHOD.md',(ROOT/'docs/EXPERIMENTAL_ANALYTICS.md').read_text())
        return Response(buffer.getvalue(),media_type='application/zip',headers={'Content-Disposition':'attachment; filename="experimental_analytics.zip"'})
    @app.post('/api/analytics/import')
    async def analytics_import(request:Request):
        analytics_idle()
        raw=await request.body()
        try:return await background(lambda:analytics.import_archive(raw))
        except (ValueError,KeyError,TypeError,RuntimeError,zipfile.BadZipFile) as exc:raise HTTPException(400,str(exc)) from exc
    app.mount('/static',StaticFiles(directory=ROOT/'benign_lab/static'),name='static')
    @app.get('/')
    def index(): return FileResponse(ROOT/'benign_lab/static/index.html')
    return app
