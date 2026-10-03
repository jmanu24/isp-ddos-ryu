from __future__ import annotations
import asyncio
from asyncio import TimeoutError
import copy
import csv
import io
import json
import os
import signal
import time
import uuid
from collections import Counter
from pathlib import Path
from .config import resolve, supervisor_groups
from .execution import execution_options
from .transport import SupervisorSession
from .clock_sync import probe_clock
from .baseline import BaselineGuard
from .ground_truth import windows
from .planner import canonical, digest, validate

TERMINAL = {'completed','completed_with_errors','failed','stopped','interrupted'}


def atomic_json(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_bytes(canonical(value)+b'\n')
    tmp.replace(path)


def csv_text(rows):
    if not rows: return ''
    out=io.StringIO()
    fields=list(dict.fromkeys(key for row in rows for key in row))
    writer=csv.DictWriter(out,fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


class Manager:
    def __init__(self, root):
        self.root=Path(root)
        self.root.mkdir(parents=True,exist_ok=True)
        self.runs={}
        self.tasks={}
        self.stops={}
        self.processes={}
        self.supervisors={}
        self.events={}
        self.logs={}
        self.origins={}
        self.plan_cache={}
        self.checkpoint_lock=None
        self.terminal_metrics={}
        for file in sorted(self.root.glob('*/run.json')):
            run=json.loads(file.read_text())
            eid=run['id']
            self.runs[eid]=run
            ep=file.parent/'event_states.json'
            self.events[eid]=json.loads(ep.read_text()) if ep.exists() else {}
            lp=file.parent/'logs.jsonl'
            self.logs[eid]=[json.loads(line) for line in lp.read_text().splitlines()[-200:] if line.strip()] if lp.exists() else []
            if run['status'] not in TERMINAL:
                run.update(status='interrupted',error='Orchestrator restarted; no automatic replay',finished_at=time.time())
                for e in self.events[eid].values():
                    if e['status'] in ('pending','running'): e['status']='interrupted'
                self.persist(eid)

    def folder(self, rid): return self.root/rid

    def elapsed(self,rid):
        r=self.runs[rid]
        if r['status'] in TERMINAL or rid not in self.origins: return r.get('elapsed_s',0)
        return min(r['duration_s'],max(0,(time.monotonic()-self.origins[rid])*(r['speed'] if r['mode']=='simulation' else 1)))

    def snapshot(self,rid):
        r=copy.deepcopy(self.runs[rid])
        r['elapsed_s']=self.elapsed(rid)
        cached=self.terminal_metrics.get(rid) if r['status'] in TERMINAL and r.get('finished_at') else None
        if cached is not None:
            r.update(copy.deepcopy(cached))
        else:
            r['counts']=dict(Counter(e['status'] for e in self.events[rid].values()))
            r['bytes_tx']=sum(e.get('bytes_tx',0) for e in self.events[rid].values())
            r['bytes_rx']=sum(e.get('bytes_rx',0) for e in self.events[rid].values())
            r['shortfall_bytes']=sum(e.get('shortfall_bytes',0) for e in self.events[rid].values())
            r['active_planned_mbps']=sum(e['rate_bps'] for e in self.events[rid].values() if e['status']=='running')/1e6
            r['domains']={}
            for domain in ('mobile','fixed','enterprise','peering'):
                es=[e for e in self.events[rid].values() if e['domain']==domain]
                r['domains'][domain]=dict(counts=dict(Counter(e['status'] for e in es)),bytes_tx=sum(e.get('bytes_tx',0) for e in es),bytes_rx=sum(e.get('bytes_rx',0) for e in es),active_planned_mbps=sum(e['rate_bps'] for e in es if e['status']=='running')/1e6)
            if r['status'] in TERMINAL and r.get('finished_at'):
                self.terminal_metrics[rid]={k:copy.deepcopy(r[k]) for k in ('counts','bytes_tx','bytes_rx','shortfall_bytes','active_planned_mbps','domains')}
        if r.get('purpose')=='domain_benchmark':
            actual=r['bytes_tx']+r['bytes_rx'];planned=r['benchmark_planned_bytes']
            r['benchmark_metrics']=dict(domain=r['benchmark_domain'],planned_bytes=planned,actual_bytes=actual,observed_pct=100*actual/planned,planned_mean_mbps=planned*8/r['duration_s']/1e6,observed_mean_mbps=actual*8/max(r['elapsed_s'],.001)/1e6,failed_events=r['counts'].get('failed',0),final=r['status'] in TERMINAL)
        r['logs']=self.logs[rid][-100:]
        return r

    def log(self,rid,message,level='info'):
        row=dict(timestamp=time.time(),level=level,message=message)
        self.logs[rid].append(row)
        self.logs[rid]=self.logs[rid][-200:]
        with (self.folder(rid)/'logs.jsonl').open('a') as f: f.write(json.dumps(row)+'\n')

    def checkpoint(self,rid):
        self.runs[rid]['elapsed_s']=self.elapsed(rid)
        if rid not in self.plan_cache:
            self.plan_cache[rid]=json.loads((self.folder(rid)/'benign_plan.json').read_text())
        return (self.folder(rid),copy.deepcopy(self.runs[rid]),copy.deepcopy(self.events[rid]),self.plan_cache[rid])

    @staticmethod
    def write_checkpoint(snapshot):
        folder,r,events,plan=snapshot
        atomic_json(folder/'run.json',r)
        atomic_json(folder/'event_states.json',events)
        for name,rows in (('ground_truth_windows.csv',windows(plan,r)),('generated_events.csv',list(events.values()))):
            target=folder/name;tmp=target.with_suffix('.tmp')
            tmp.write_text(csv_text(rows));tmp.replace(target)

    def persist(self,rid):
        # Synchronous recovery before the event loop starts.
        self.write_checkpoint(self.checkpoint(rid))

    async def persist_async(self,rid,after=None):
        if self.checkpoint_lock is None:self.checkpoint_lock=asyncio.Lock()
        async with self.checkpoint_lock:
            snapshot=self.checkpoint(rid)
            def work():
                self.write_checkpoint(snapshot)
                return after() if after else None
            future=asyncio.get_running_loop().run_in_executor(None,work)
            try:return await asyncio.shield(future)
            except asyncio.CancelledError:
                # Threads cannot be canceled. Keep the lock until the writer
                # has finished so shutdown cannot overlap a newer checkpoint.
                await future
                raise

    async def start(self,plan,plan_file,cfg,mode='simulation',scenario='B0',speed=20,attack_windows=None,pipeline='enabled',execution_profile=None):
        validate(plan)
        if plan.get('purpose')=='domain_benchmark' and (scenario!='B0' or attack_windows or (mode=='lab' and pipeline!='baseline')):
            raise ValueError('Domain benchmark requires B0 without attacks and baseline pipeline for laboratory runs')
        cfg=copy.deepcopy(cfg)
        options=execution_options(cfg,execution_profile)
        cfg['execution_options']=options
        if pipeline not in ('enabled','baseline'): raise ValueError('Invalid pipeline option')
        if pipeline=='baseline' and (mode!='lab' or scenario!='B0' or attack_windows):
            raise ValueError('Baseline requires laboratory B0 without attacks')
        if pipeline=='baseline' and not cfg.get('baseline_control'):
            raise ValueError('Baseline controller mapping is not configured')
        if any(r['status'] not in TERMINAL for r in self.runs.values()):
            raise ValueError('An experiment is already active; concurrent runs would contaminate the baseline')
        if mode not in ('simulation','lab') or scenario not in ('B0','B0+attack'):
            raise ValueError('Invalid mode/scenario')
        if mode=='lab' and speed!=1: raise ValueError('Laboratory runs require speed=1')
        if not .1<=speed<=100: raise ValueError('Invalid simulation speed')
        attack_windows=attack_windows or []
        if scenario=='B0' and attack_windows: raise ValueError('B0 cannot contain attack windows')
        for w in attack_windows:
            if not 0<=w['start_s']<w['end_s']<=plan['duration_s']: raise ValueError('Invalid attack window')
        groups=resolve(cfg,plan) if mode=='lab' else {}
        rid=time.strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]
        folder=self.folder(rid)
        folder.mkdir()
        # Exact byte copy: experiment metadata is never written into the plan.
        (folder/'benign_plan.json').write_bytes(Path(plan_file).read_bytes())
        atomic_json(folder/'lab_snapshot.json',cfg)
        r=dict(id=rid,status='preparing',created_at=time.time(),started_at=None,finished_at=None,
               purpose=plan.get('purpose','baseline_plan'),benchmark_domain=plan.get('benchmark_domain'),benchmark_planned_bytes=sum(e['planned_bytes'] for e in plan['events']) if plan.get('purpose')=='domain_benchmark' else None,
               plan_hash=plan['plan_hash'],plan_file_sha256=__import__('hashlib').sha256(Path(plan_file).read_bytes()).hexdigest(),
               lab_hash=digest(cfg),seed=plan['seed'],duration_s=plan['duration_s'],mode=mode,scenario=scenario,speed=speed,
               plan_capacity_mbps=copy.deepcopy(plan['capacity_mbps']),lab_reference_capacity_mbps=copy.deepcopy(cfg.get('capacity_mbps')),
               capacities_differ=cfg.get('capacity_mbps')!=plan['capacity_mbps'],
               elapsed_s=0,attack_windows=attack_windows,observed_attacks=[],error=None,
               pipeline=pipeline,execution_profile=options['profile'],execution_options=options,execution_hash=digest(options),baseline_control={},metrics_kind='simulated_payload' if mode=='simulation' else 'application_payload')
        self.runs[rid]=r
        self.plan_cache[rid]=plan
        atomic_json(folder/'execution_profile.json',dict(execution_hash=r['execution_hash'],options=options,plan_hash=plan['plan_hash']))
        self.events[rid]={e['event_id']:dict(e,status='pending',bytes_tx=0,bytes_rx=0,chunks_tx=0,chunks_rx=0,
                         icmp_replies=0,src_port=None,dst_port=None,actual_start_s=None,actual_end_s=None,
                         start_timestamp=None,stop_timestamp=None,lateness_s=None,error=None) for e in plan['events']}
        self.logs[rid]=[]
        self.stops[rid]=asyncio.Event()
        self.processes[rid]=[]
        self.log(rid,f'{scenario} | {mode} | immutable plan {plan["plan_hash"]}')
        if r['capacities_differ']:
            self.log(rid,'Custom plan capacities (Mbps): '+json.dumps(r['plan_capacity_mbps'],sort_keys=True)+'; unchanged lab reference: '+json.dumps(r['lab_reference_capacity_mbps'],sort_keys=True))
        try:
            await self.persist_async(rid)
        except Exception as exc:
            r.update(status='failed',error=f'Could not initialize artifacts: {exc}',finished_at=time.time())
            raise ValueError(r['error']) from exc
        self.tasks[rid]=asyncio.create_task(self.execute(rid,plan,cfg,groups))
        return self.snapshot(rid)

    async def execute(self,rid,plan,cfg,groups):
        r=self.runs[rid]
        guard=None
        try:
            if r['pipeline']=='baseline':
                cfg=copy.deepcopy(cfg)
                guard=BaselineGuard(cfg,rid,plan['duration_s'])
                if plan.get('purpose')=='domain_benchmark':guard.domains={plan['benchmark_domain']}
                self.log(rid,'Suspending detection and mitigation for baseline')
                r['baseline_control']['preflight']=await guard.enter()
                groups=resolve(cfg,plan)
                r['lab_hash']=digest(cfg)
                atomic_json(self.folder(rid)/'lab_snapshot.json',cfg)
                await self.persist_async(rid)
                self.log(rid,'Baseline acknowledged; selected domain checks completed' if plan.get('purpose')=='domain_benchmark' else 'Baseline acknowledged; UE budgets restored and ten Fixed sessions verified')
            if r['mode']=='simulation':
                await self.simulate(rid,plan)
            else:
                if guard:
                    traffic=asyncio.create_task(self.real(rid,plan,cfg,groups))
                    monitor=asyncio.create_task(guard.monitor())
                    try:
                        done,_=await asyncio.wait((traffic,monitor),return_when=asyncio.FIRST_COMPLETED)
                        if monitor in done:await monitor
                        await traffic
                    finally:
                        for task in (traffic,monitor):
                            if not task.done():task.cancel()
                        await asyncio.gather(traffic,monitor,return_exceptions=True)
                else:
                    await self.real(rid,plan,cfg,groups)
            if self.stops[rid].is_set(): r['status']='stopped'
            else:
                r['status']='completed_with_errors' if any(e['status']=='failed' or e.get('error') for e in self.events[rid].values()) else 'completed'
        except Exception as exc:
            r.update(status='failed',error='%s: %s' % (type(exc).__name__,str(exc) or 'Operation timed out during preparation/execution'))
            import traceback
            (self.folder(rid)/'failure_traceback.txt').write_text(traceback.format_exc())
            self.log(rid,r['error'],'error')
        finally:
            # Freeze the elapsed value before removing the monotonic clock.
            if rid in self.origins:
                factor=r['speed'] if r['mode']=='simulation' else 1
                r['elapsed_s']=min(r['duration_s'],max(0,(time.monotonic()-self.origins[rid])*factor))
            await self.kill_processes(rid)
            if guard:
                try:
                    r['baseline_control']['restoration']=await guard.leave()
                    self.log(rid,'Detection and mitigation restored after baseline')
                except Exception as exc:
                    r.update(status='failed',error='Baseline restoration failed: '+str(exc))
                    r['baseline_control']['restoration']=dict(restored=False,error=str(exc))
                    self.log(rid,r['error'],'error')
            for e in self.events[rid].values():
                if e['status'] in ('pending','running'):
                    e['status']='cancelled' if r['status']=='stopped' else 'failed'
                    e['error']='Run ended before event completion'
            for a in r['observed_attacks']:
                if a.get('end_s') is None: a['end_s']=r['elapsed_s']
            if r['status']=='completed' and any(e['status']=='failed' for e in self.events[rid].values()):
                r['status']='completed_with_errors'
            r['payload_mbps']=0
            r['finished_at']=time.time()
            self.log(rid,f'Run {r["status"]}')
            await self.persist_async(rid)

    async def simulate(self,rid,plan):
        r=self.runs[rid]
        speed=r['speed']
        origin=time.monotonic()
        self.origins[rid]=origin
        r.update(status='running',started_at=time.time())
        self.log(rid,'Simulation only: no laboratory traffic is emitted.')
        while True:
            elapsed=min(plan['duration_s'],(time.monotonic()-origin)*speed)
            r['elapsed_s']=elapsed
            for e in self.events[rid].values():
                progress=1.0 if elapsed+1e-6>=e['start_s']+e['duration_s'] else max(0,min(1,(elapsed-e['start_s'])/e['duration_s']))
                if elapsed<e['start_s']: continue
                if e['status']=='pending':
                    e.update(status='running',actual_start_s=e['start_s'],start_timestamp=r['started_at']+e['start_s']/speed,lateness_s=0)
                kind='rx' if e['direction']=='dl' else 'tx'
                e[f'bytes_{kind}']=int(e['planned_bytes']*progress)
                e[f'chunks_{kind}']=math_ceil(e[f'bytes_{kind}']/e['packet_size_bytes'])
                if progress>=1:
                    e.update(status='completed',actual_end_s=e['start_s']+e['duration_s'],stop_timestamp=r['started_at']+(e['start_s']+e['duration_s'])/speed)
            if elapsed>=plan['duration_s'] or self.stops[rid].is_set(): break
            await asyncio.sleep(.1)
        r['elapsed_s']=elapsed

    async def real(self,rid,plan,cfg,groups):
        r=self.runs[rid]
        options=cfg.get('execution_options',execution_options(cfg))
        sessions=[];channels={}
        if options['supervisor_per_vm']:
            bundles=supervisor_groups(groups)
            async def launch(sid,bundle):
                proc=await asyncio.create_subprocess_exec(*bundle['argv'],stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=True,limit=32*1024*1024)
                self.processes[rid].append(proc)
                session=SupervisorSession(proc,[w['key'] for w in bundle['workers']]);sessions.append(session)
                self.supervisors.setdefault(rid,[]).append(session)
                workers=[]
                for worker in bundle['workers']:
                    key,group=worker['key'],worker['group']
                    group['supervisor_id']=sid
                    workers.append(dict(key=key,argv=worker['argv'],config=dict(events=group['events'],targets=cfg['targets'],duration_s=plan['duration_s'],context=group['context'],execution=options)))
                proc.stdin.write(canonical(dict(workers=workers))+b'\n');await proc.stdin.drain()
                channels.update(session.channels)
            results=await asyncio.gather(*(launch(sid,bundle) for sid,bundle in bundles.items()),return_exceptions=True)
            errors=[e for e in results if isinstance(e,Exception)]
            if errors:raise errors[0]
            r['execution_transport']=dict(kind='supervisor_per_vm',sessions=len(bundles),workers=len(groups))
        else:r['execution_transport']=dict(kind='ssh_per_worker',sessions=len(groups),workers=len(groups))
        async def prepare(key,group):
            group['key']=key
            if options['supervisor_per_vm']:
                proc=channels[key]
            else:
                proc=await asyncio.create_subprocess_exec(*group['argv'],stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=True,limit=32*1024*1024)
                self.processes[rid].append(proc)
                payload=dict(events=group['events'],targets=cfg['targets'],duration_s=plan['duration_s'],context=group['context'],execution=options)
                proc.stdin.write(canonical(payload)+b'\n');await proc.stdin.drain()
            line=await asyncio.wait_for(proc.stdout.readline(),30)
            if not line:
                err=(await proc.stderr.read(2000)).decode(errors='replace')
                raise RuntimeError(f'Agent {key} did not start: {err}')
            reply=json.loads(line)
            if reply['type']!='ready': raise RuntimeError(f'Agent {key}: {reply.get("error",reply)}')
            if (options['metrics_batch'] or options['connection_reuse']) and reply.get('protocol_version')!=2:
                raise RuntimeError('Worker protocol v2 required; deploy updated agents')
            group['evidence']=reply.get('evidence',{})
            self.runs[rid].setdefault('agents',{})[key]=dict(sources=sorted(group['sources']),context=group['context'],evidence=group['evidence'],status='ready',supervisor_id=group.get('supervisor_id'),python_version=reply.get('python_version'),pid=reply.get('pid'))
            atomic_json(self.folder(rid)/'execution_mapping.json',self.runs[rid]['agents'])
            self.log(rid,f'Agent ready: {", ".join(sorted(group["sources"]))}')
            return proc,group
        # Await all preparations, including failures, so no orphaned launch remains.
        prepared=await asyncio.gather(*(prepare(k,g) for k,g in groups.items()),return_exceptions=True)
        errors=[p for p in prepared if isinstance(p,Exception)]
        if errors: raise errors[0]
        # Probe only after all plan uploads/preflights finish; the ready message
        # may have waited in SSH or in the controller's event loop.
        for key,(proc,group) in zip(groups,prepared):
            if self.stops[rid].is_set(): return
            try:
                clock=await probe_clock(proc,cfg.get('max_clock_skew_s',.5))
            except Exception as exc:
                raise RuntimeError('Clock probe for '+', '.join(sorted(group['sources']))+': '+(str(exc) or type(exc).__name__)) from exc
            r['agents'][key]['clock']=clock
            r['agents'][key]['status']='ready' if clock['status']=='synchronized' else 'clock_'+clock['status']
            atomic_json(self.folder(rid)/'execution_mapping.json',r['agents'])
            sources=', '.join(sorted(group['sources']))
            detail=f"offset={clock['offset_s']:.6f}s, uncertainty={clock['uncertainty_s']:.6f}s, RTT={clock['round_trip_s']:.6f}s"
            self.log(rid,f'Clock {sources}: {clock["status"]}; {detail}')
            if clock['status']=='skewed':
                raise RuntimeError(f'Agent {sources} clock exceeds allowed skew; synchronize NTP ({detail})')
            if clock['status']=='inconclusive':
                raise RuntimeError(f'Agent {sources} clock check inconclusive due to communication latency; retry when load is lower ({detail})')
        if self.stops[rid].is_set(): return
        start=time.time()+cfg.get('start_lead_s',3)
        self.origins[rid]=time.monotonic()+start-time.time()
        r.update(status='running',started_at=start)
        for proc,group in prepared:
            proc.stdin.write(canonical(dict(start_unix=start))+b'\n')
            await proc.stdin.drain()
        self.log(rid,f'All agents scheduled for epoch {start:.6f}')
        r['worker_messages']=dict(total=0,metric_batches=0,metrics=0)
        async def read(proc,group):
            done=False
            async def stderr():
                while line:=await proc.stderr.readline():
                    self.log(rid,line.decode(errors='replace')[:1000],'warning')
            errtask=asyncio.create_task(stderr())
            try:
                while line:=await proc.stdout.readline():
                    envelope=json.loads(line)
                    r['worker_messages']['total']+=1
                    if envelope['type']=='metrics_batch':r['worker_messages']['metric_batches']+=1
                    if envelope['type'] in ('metrics','metrics_batch'):
                        r['worker_messages']['metrics']+=len(envelope['items']) if envelope['type']=='metrics_batch' else 1
                    if envelope['type']=='done': done=True
                    if envelope['type']=='worker_stats':
                        r['agents'][group['key']]['connections']=envelope['connections']
                    messages=[dict(type='metrics',**item) for item in envelope['items']] if envelope['type']=='metrics_batch' else [envelope]
                    for msg in messages:
                        if msg['type'] not in ('event','metrics'):continue
                        e=self.events[rid].get(msg['event_id'])
                        if e is None: raise ValueError('Agent returned unknown event')
                        for key in ('status','bytes_tx','bytes_rx','chunks_tx','chunks_rx','icmp_replies','src_port','dst_port','actual_start_s','actual_end_s','start_timestamp','stop_timestamp','lateness_s','error','source_ip','source_interface','shortfall_bytes','receiver_bytes','connections_opened','connection_reused'):
                            if key in msg: e[key]=msg[key]
                        if msg['type']=='event':
                            with (self.folder(rid)/'events.jsonl').open('a') as f: f.write(json.dumps(msg)+'\n')
                            if msg.get('error'): self.log(rid,f'{e["event_id"]}: {msg.get("error")}', 'error' if msg.get('status')=='failed' else 'warning')
                await proc.wait()
                if proc.returncode or not done:
                    raise RuntimeError(f'Agent disconnected (exit={proc.returncode}); run incomplete')
            finally:
                errtask.cancel()
                await asyncio.gather(errtask,return_exceptions=True)
        reads=[asyncio.create_task(read(proc,group)) for proc,group in prepared]
        joined=asyncio.gather(*reads)
        stop=asyncio.create_task(self.stops[rid].wait())
        deadline=asyncio.create_task(asyncio.sleep(max(0,start-time.time())+plan['duration_s']+10))
        try:
            done,_=await asyncio.wait([joined,stop,deadline],return_when=asyncio.FIRST_COMPLETED)
            if joined in done:
                await joined
                # A plan with early-ending events still observes the whole interval.
                remaining=max(0,self.origins[rid]+plan['duration_s']-time.monotonic())
                try: await asyncio.wait_for(self.stops[rid].wait(),remaining)
                except TimeoutError: pass
            elif stop not in done:
                raise RuntimeError('Agents exceeded the experiment deadline')
        finally:
            await self.kill_processes(rid)
            for task in reads+[stop,deadline]: task.cancel()
            await asyncio.gather(*reads,stop,deadline,return_exceptions=True)
            if not joined.done(): joined.cancel()
            await asyncio.gather(joined,return_exceptions=True)
            await asyncio.gather(*(session.task for session in sessions),return_exceptions=True)

    async def kill_processes(self,rid):
        live=[p for p in self.processes.get(rid,[]) if p.returncode is None]
        for p in live:
            try:
                p.stdin.write(b'STOP\n')
                await p.stdin.drain()
                p.stdin.close()
            except (OSError,ConnectionError): pass
        for p in live:
            try: await asyncio.wait_for(p.wait(),2)
            except TimeoutError:
                try: os.killpg(p.pid,signal.SIGTERM)
                except ProcessLookupError: pass
                try: await asyncio.wait_for(p.wait(),1)
                except TimeoutError:
                    try: os.killpg(p.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                    await p.wait()
        for session in self.supervisors.get(rid,[]):
            await asyncio.gather(session.task,session.error_task,return_exceptions=True)
        if self.supervisors.get(rid) and rid in self.runs:
            self.runs[rid]['supervisor_transport_stats']=[session.stats for session in self.supervisors[rid]]

    async def stop(self,rid):
        if self.runs[rid]['status'] not in TERMINAL:
            self.stops[rid].set()
            self.log(rid,'Stop requested')
        return self.snapshot(rid)

    async def shutdown(self):
        for rid in self.tasks:
            if not self.tasks[rid].done(): self.stops[rid].set()
        await asyncio.gather(*self.tasks.values(),return_exceptions=True)

    def annotate(self,rid,name,action):
        r=self.runs[rid]
        if r['status']!='running' or r['scenario']!='B0+attack': raise ValueError('Requires a running B0+attack experiment')
        elapsed=self.elapsed(rid)
        if action=='start':
            if any(a['name']==name and a.get('end_s') is None for a in r['observed_attacks']): raise ValueError('Attack already marked active')
            r['observed_attacks'].append(dict(name=name,start_s=elapsed,end_s=None))
        elif action=='stop':
            matches=[a for a in r['observed_attacks'] if a['name']==name and a.get('end_s') is None]
            if not matches: raise ValueError('No active attack with this name')
            matches[-1]['end_s']=elapsed
        else: raise ValueError('Invalid annotation action')
        self.log(rid,f'External attack {name}: {action} at {elapsed:.3f} s')
        return self.snapshot(rid)


def math_ceil(x):
    return __import__('math').ceil(x)
