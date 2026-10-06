import asyncio
import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace
import pytest
from benign_lab.experiment_jobs import ExperimentJobs

class Fake:
    def __init__(self): self.runs={};self.tasks={};self.started=[]
    async def persist_async(self,rid): pass
    async def start(self,request):
        rid=str(len(self.started));self.started.append(request.copy())
        self.runs[rid]={'status':'running','mode':'simulation','pipeline':'enabled'}
        async def complete():
            await asyncio.sleep(.01);self.runs[rid]['status']='completed'
        self.tasks[rid]=asyncio.create_task(complete())
        return {'id':rid}

def setup(tmp_path):
    p=tmp_path/'plan.json';p.write_bytes(b'{"immutable":true}')
    m=Fake();lock=None
    def locking():
        nonlocal lock
        if lock is None: lock=asyncio.Lock()
        return lock
    q=ExperimentJobs(tmp_path,m,locking,m.start,lambda ph:p)
    return q,m,p

def test_serial_repeats_and_exact_request(tmp_path):
    async def run():
        q,m,p=setup(tmp_path);j=q.create({'plan_hash':'x','pipeline':'enabled'},3);j=q.jobs[j['id']]
        for i in range(3):await q.tick()
        assert j['status']=='completed' and len(j['run_ids'])==3
        assert all(r==m.started[0] for r in m.started)
        assert p.read_bytes()==b'{"immutable":true}'
        assert [m.runs[x]['repetition_index'] for x in j['run_ids']]==[1,2,3]
    asyncio.run(run())

def test_future_and_existing_run_wait(tmp_path):
    async def run():
        q,m,p=setup(tmp_path);j=q.create({'plan_hash':'x'},scheduled_at=time.time()+100);j=q.jobs[j['id']]
        await q.tick();assert not m.started
        j['next_at']=0;m.runs['manual']={'status':'preparing'}
        await q.tick();assert not m.started
    asyncio.run(run())

def test_plan_tamper_fails_without_execution(tmp_path):
    async def run():
        q,m,p=setup(tmp_path);q.create({'plan_hash':'x'});p.write_bytes(b'changed');await q.tick()
        assert not m.started and next(iter(q.jobs.values()))['status']=='failed'
    asyncio.run(run())

def test_cancel_pending_and_cancel_running(tmp_path):
    async def run():
        q,m,p=setup(tmp_path);j=q.create({'plan_hash':'x'},3);j=q.jobs[j['id']];q.cancel(j['id']);await q.tick();assert not m.started
        j=q.create({'plan_hash':'x'},3);j=q.jobs[j['id']];t=asyncio.create_task(q.tick());await asyncio.sleep(.002);q.cancel(j['id']);await t
        assert j['status']=='cancelled' and len(m.started)==1
    asyncio.run(run())

def test_restart_ambiguous_requires_attention(tmp_path):
    q,m,p=setup(tmp_path);j=q.create({'plan_hash':'x'},3);j=q.jobs[j['id']];j['status']='starting';q.save()
    restored=ExperimentJobs(tmp_path,m,q.lock,m.start,lambda ph:p)
    assert restored.jobs[j['id']]['status']=='attention'

def test_pending_survives_restart_and_references(tmp_path):
    q,m,p=setup(tmp_path);j=q.create({'plan_hash':'x'},3,scheduled_at=time.time()+100);j=q.jobs[j['id']]
    restored=ExperimentJobs(tmp_path,m,q.lock,m.start,lambda ph:p)
    assert restored.references('x') and restored.jobs[j['id']]['status']=='pending'
    restored.cancel(j['id']);assert not restored.references('x')

def test_bad_timestamp(tmp_path):
    q,m,p=setup(tmp_path)
    with pytest.raises(ValueError):q.create({'plan_hash':'x'},scheduled_at=float('nan'))
    with pytest.raises(ValueError):q.create({'plan_hash':'x'},scheduled_at=0)

def test_pause_and_failure_stop_series(tmp_path):
    async def run():
        q,m,p=setup(tmp_path);j=q.create({'plan_hash':'x'},3,gap_s=100);j=q.jobs[j['id']]
        await q.tick();assert j['status']=='pending' and j['next_at']>time.time()
        await q.tick();assert len(m.started)==1
        j['next_at']=0
        original=m.start
        async def fail(request):
            result=await original(request)
            async def failed():
                await asyncio.sleep(.005);m.runs[result['id']]['status']='failed'
            m.tasks[result['id']]=asyncio.create_task(failed())
            return result
        q.start=fail
        await q.tick();assert j['status']=='failed'
        await q.tick();assert len(m.started)==2
    asyncio.run(run())

def test_no_repeat_if_pipeline_restoration_unverified(tmp_path):
    async def run():
        q,m,p=setup(tmp_path);original=m.start
        async def baseline(request):
            r=await original(request);m.runs[r['id']].update(mode='lab',pipeline='baseline',baseline_control={'restoration':{'restored':False}})
            return r
        q.start=baseline;j=q.create({'plan_hash':'x'},3);j=q.jobs[j['id']]
        await q.tick();assert j['status']=='attention' and len(m.started)==1
    asyncio.run(run())
