import asyncio,time
import pytest
from test_experiment_jobs import setup

def test_comparison_order_pause_duplicate_and_references(tmp_path):
 async def run():
  q,m,p=setup(tmp_path);steps=[dict(plan_hash=str(i%3),execution_profile='classic' if i%2==0 else 'persistent') for i in range(18)]
  j=q.create_comparison(steps);j=q.jobs[j['id']]
  assert all(q.references(str(i)) for i in range(3))
  with pytest.raises(ValueError):q.create_comparison(steps)
  for i in range(18):
   j['next_at']=0;await q.tick()
   if i<17:
    assert j['next_at']>=time.time()+59
    await q.tick();assert len(m.started)==i+1
  assert m.started==steps and j['status']=='completed'
  assert not any(q.references(str(i)) for i in range(3))
 asyncio.run(run())

def test_comparison_tampered_later_plan_stops(tmp_path):
 async def run():
  q,m,p=setup(tmp_path);q.create_comparison([dict(plan_hash='first'),dict(plan_hash='second')]);j=next(iter(q.jobs.values()));await q.tick();p.write_bytes(b'tampered');j['next_at']=0;await q.tick()
  assert j['status']=='failed' and len(m.started)==1
 asyncio.run(run())

def test_comparison_api_preview_and_queue(tmp_path):
 import shutil
 from pathlib import Path
 from fastapi.testclient import TestClient
 from benign_lab.api import create_app
 from benign_lab.config import ROOT
 source=Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/data/plans');(tmp_path/'plans').mkdir()
 hashes=['2c3580be4272c69a94c0ee39a990b0d33b9aa8654f60ab35d120283d2e118245','18aa3c08e732aa6ac773f09538ccabe6df629ee3effb8d02b0d191f2538dbd1c','aace0dfc7bc48ca29417b543acc1b6e3c8c40c3ba34644f834b8f11179a8b948']
 for h in hashes:shutil.copy(source/(h+'.json'),tmp_path/'plans'/(h+'.json'))
 app=create_app(tmp_path,ROOT/'config/lab.connected.yaml');app.state.experiment_jobs.launch=lambda:None
 with TestClient(app) as c:
  r=c.get('/api/comparison-plan');assert r.status_code==200
  steps=r.json()['steps'];assert len(steps)==18 and all(x['pipeline']=='baseline' for x in steps)
  assert all(x['execution_profile']=='classic' for x in steps)
  for seed in [1,2,3]:assert sum(x['seed']==seed for x in steps)==6
  assert [x['seed'] for x in steps]==[1,2,3,2,3,1,3,1,2,1,3,2,3,2,1,2,1,3]
  job=c.post('/api/comparison-plan/start',json={});assert job.status_code==200 and job.json()['count']==18
  assert c.post('/api/comparison-plan/start',json={}).status_code==400
  assert c.post('/api/jobs/'+job.json()['id']+'/cancel',json={}).status_code==200
