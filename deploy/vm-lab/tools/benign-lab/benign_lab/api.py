from __future__ import annotations
import asyncio
import contextlib
import io
import json
import os
import re
import secrets
import time
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, Dict, List
from .config import ROOT, load_lab, resolve, mapping_issues
from .ground_truth import windows
from .planner import DOMAINS, canonical, generate, load_profiles, save_plan, validate
from .runner import Manager, TERMINAL, csv_text


class PlanRequest(BaseModel):
    seed: int = 1
    duration_s: float = Field(default=600, ge=5, le=3600)
    capacity_mbps: Optional[Dict[str,float]] = None

class AttackWindow(BaseModel):
    name: str = Field(min_length=1,max_length=80)
    start_s: float = Field(ge=0,allow_inf_nan=False)
    end_s: float = Field(gt=0,allow_inf_nan=False)

class RunRequest(BaseModel):
    plan_hash: str
    mode: str = 'simulation'
    scenario: str = 'B0'
    pipeline: str = 'enabled'
    speed: float = Field(default=20,ge=.1,le=100)
    attack_windows: List[AttackWindow] = Field(default_factory=list,max_length=100)

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
    previous={}
    async def monitor():
        tick=0
        while True:
            await asyncio.sleep(1)
            tick+=1
            for rid,r in list(manager.runs.items()):
                if r['status'] in TERMINAL: continue
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
                if tick%5==0: manager.persist(rid)
    @asynccontextmanager
    async def lifespan(app):
        task=asyncio.create_task(monitor())
        yield
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError): await task
        await manager.shutdown()
    app=FastAPI(title='BENIGN Lab',version='1.0.0',lifespan=lifespan)
    app.state.manager=manager
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
    def read_plan(ph): return validate(json.loads(path_for(ph).read_text()))
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
            rows.append({k:p[k] for k in ('plan_hash','seed','duration_s','summary','warnings','capacity_mbps')})
        return rows[::-1]
    @app.post('/api/plans')
    def make_plan(body:PlanRequest):
        p=generate(load_profiles(profiles_path),body.seed,body.duration_s,body.capacity_mbps or load_lab(lab_path)['capacity_mbps'])
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
    def download_plan(ph:str): return FileResponse(path_for(ph),filename='benign_plan.json',media_type='application/json')
    @app.post('/api/plans/{ph}/preflight')
    def preflight(ph:str):
        groups=resolve(load_lab(lab_path),read_plan(ph))
        return dict(ok=True,scope='configuration_only; connectivity checked on lab start',groups=[dict(sources=sorted(g['sources']),events=len(g['events']),command=g['argv'],context=g['context']) for g in groups.values()])
    @app.get('/api/runs')
    async def list_runs(): return [manager.snapshot(rid) for rid in reversed(manager.runs)]
    @app.post('/api/runs')
    async def start_run(body:RunRequest):
        p=read_plan(body.plan_hash)
        return await manager.start(p,path_for(body.plan_hash),load_lab(lab_path),body.mode,body.scenario,body.speed,[w.model_dump() for w in body.attack_windows],body.pipeline)
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
        return manager.annotate(rid,body.name,body.action)
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
        run_for(rid)
        manager.persist(rid)
        buffer=io.BytesIO()
        with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as z:
            for f in manager.folder(rid).iterdir():
                if f.suffix in ('.json','.jsonl','.csv'): z.write(f,f.name)
        return Response(buffer.getvalue(),media_type='application/zip',headers={'Content-Disposition':f'attachment; filename="{rid}.zip"'})
    app.mount('/static',StaticFiles(directory=ROOT/'benign_lab/static'),name='static')
    @app.get('/')
    def index(): return FileResponse(ROOT/'benign_lab/static/index.html')
    return app
