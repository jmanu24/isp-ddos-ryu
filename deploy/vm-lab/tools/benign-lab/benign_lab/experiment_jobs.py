import asyncio
import hashlib
import json
import math
import time
import uuid
from pathlib import Path

TERMINAL = {'completed', 'completed_with_errors', 'failed', 'stopped', 'interrupted'}
JOB_TERMINAL = {'completed', 'failed', 'cancelled', 'attention'}

class ExperimentJobs:
    """One persistent serial queue. Ambiguous starts are never retried automatically."""
    def __init__(self, data, manager, lock, start, plan_path):
        self.path = Path(data) / 'experiment_jobs.json'
        self.manager, self.lock, self.start, self.plan_path = manager, lock, start, plan_path
        self.jobs = json.loads(self.path.read_text()) if self.path.exists() else {}
        for job in self.jobs.values():
            if job['status'] in ('starting', 'running'):
                job['status'] = 'attention'
                job['error'] = 'Servidor reiniciado durante la serie. Revise la última ejecución; no se repite automáticamente.'
        self.task = None
        self.save()

    def save(self):
        tmp = self.path.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.jobs, ensure_ascii=False, indent=2), encoding='utf-8')
        tmp.replace(self.path)

    def active(self):
        return any(r['status'] not in TERMINAL for r in self.manager.runs.values()) or any(not t.done() for t in self.manager.tasks.values()) or any(not t.done() for t in self.manager.tasks.values()) or any(not t.done() for t in self.manager.tasks.values())

    def references(self, ph):
        return any(any(r['plan_hash']==ph for r in j.get('steps',[j['request']])) and j['status'] not in JOB_TERMINAL for j in self.jobs.values())

    def create(self, request, count=1, gap_s=0, scheduled_at=None, steps=None, kind='profile_comparison', labels=None):
        when = time.time() if scheduled_at is None else float(scheduled_at)
        if not math.isfinite(when) or (scheduled_at is not None and when < time.time()-5):
            raise ValueError('Seleccione una fecha futura válida')
        path = self.plan_path(request['plan_hash'])
        jid = uuid.uuid4().hex
        job = dict(id=jid, created_at=time.time(), scheduled_at=when, next_at=when,
                   count=count, gap_s=gap_s, request=request,
                   plan_file_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                   run_ids=[], status='pending', cancel_requested=False)
        if steps:
            job.update(kind=kind,steps=steps,step_labels=labels or [],step_plan_sha256=[hashlib.sha256(self.plan_path(r['plan_hash']).read_bytes()).hexdigest() for r in steps])
        self.jobs[jid] = job
        self.save()
        return dict(job)

    def create_comparison(self, steps):
        if any(j.get('kind')=='profile_comparison' and j['status'] not in JOB_TERMINAL for j in self.jobs.values()):
            raise ValueError('Ya existe una comparación pendiente o activa')
        return self.create(steps[0],len(steps),60,steps=steps)

    def continue_manual(self,jid):
        if jid not in self.jobs:raise ValueError('Series not found')
        job=self.jobs[jid]
        if job.get('kind')!='scenario_series' or job['status']!='awaiting_operator' or not job.get('manual_attack'):raise ValueError('Series is not waiting for an attack operator')
        job['status']='pending';job['next_at']=max(time.time(),job.get('next_at',0));self.save();return dict(job)

    def cancel(self, jid):
        if jid not in self.jobs: raise ValueError('Serie no encontrada')
        job = self.jobs[jid]
        if job['status'] not in JOB_TERMINAL:
            job['cancel_requested'] = True
            if job['status'] not in ('starting', 'running'): job['status'] = 'cancelled'
            self.save()
        return dict(job)

    async def tick(self):
        async with self.lock():
            if self.active(): return
            ready = sorted((j for j in self.jobs.values() if j['status'] == 'pending' and j['next_at'] <= time.time()), key=lambda j:(j['next_at'],j['created_at']))
            if not ready: return
            job = ready[0]
            try:
                request=job.get('steps',[job['request']])[len(job['run_ids'])] if job.get('steps') else job['request']
                expected=job['step_plan_sha256'][len(job['run_ids'])] if job.get('steps') else job['plan_file_sha256']
                path = self.plan_path(request['plan_hash'])
                if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    raise ValueError('Los bytes del plan cambiaron; serie detenida')
                # Persist before any side effect. A crash in this window requires human review.
                job['status'] = 'starting'
                self.save()
                result = await self.start(request)
                rid = result['id']
                job['run_ids'].append(rid)
                job['status'] = 'running'
                self.manager.runs[rid]['series_id'] = job['id']
                self.manager.runs[rid]['repetition_index'] = len(job['run_ids'])
                if job.get('kind')=='scenario_series':
                    self.manager.runs[rid].update(series_kind=job['kind'],experimental_scenario=job['experimental_scenario'],attack_source_ips=job.get('attack_source_ips',[]),attack_description=job.get('attack_description',''))
                if job.get('kind')=='profile_comparison':
                    self.manager.runs[rid]['comparison_block']=(len(job['run_ids'])-1)//6+1
                if job.get('kind')=='burst_duration_pilot':
                    self.manager.runs[rid].update(series_kind=job['kind'],burst_condition=job['step_labels'][len(job['run_ids'])-1])
                await self.manager.persist_async(rid)
                self.save()
            except Exception as exc:
                job['status'] = 'attention' if job['status']=='running' else 'failed'
                job['error'] = str(exc)
                self.save()
                return
        # The queue task waits for full cleanup, including baseline restoration.
        await asyncio.shield(self.manager.tasks[rid])
        async with self.lock():
            run = self.manager.runs[rid]
            if job['cancel_requested']: job['status'] = 'cancelled'
            elif run['status'] not in ('completed', 'completed_with_errors'):
                job['status'] = 'failed'
                job['error'] = 'Ejecución finalizada con estado ' + run['status']
            elif run.get('pipeline') == 'baseline' and run.get('mode') == 'lab' and not run.get('baseline_control', {}).get('restoration', {}).get('restored'):
                job['status'] = 'attention'
                job['error'] = 'Verifique restauración del pipeline antes de repetir'
            elif job.get('manual_attack') and not any(a.get('end_s') is not None and a['end_s']>a['start_s'] for a in run.get('observed_attacks',[])):
                job['status']='attention';job['error']='Ataque no confirmado con inicio y fin reales; serie detenida. No se cuentan ventanas previstas como ataque observado.'
            elif len(job['run_ids']) >= job['count']: job['status'] = 'completed'
            elif job.get('manual_attack'):
                job['status']='awaiting_operator';job['next_at']=time.time()+job['gap_s']
            else:
                job['status'] = 'pending'
                job['next_at'] = time.time() + job['gap_s']
            self.save()

    async def loop(self):
        while True:
            try: await self.tick()
            except asyncio.CancelledError: raise
            except Exception as exc:
                for j in self.jobs.values():
                    if j['status'] in ('starting','running'):
                        j['status']='attention'; j['error']=str(exc)
                self.save()
            await asyncio.sleep(1)

    def launch(self):
        self.task = asyncio.create_task(self.loop())

    async def shutdown(self):
        if self.task:
            self.task.cancel()
            try: await self.task
            except asyncio.CancelledError: pass
