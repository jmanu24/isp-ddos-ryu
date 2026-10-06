from fastapi.testclient import TestClient
from benign_lab.api import create_app
import time

def make(c,seed):
 return c.post('/api/plans',json=dict(seed=seed,duration_s=5,capacity_mbps=dict.fromkeys(['mobile','fixed','enterprise','peering'],10))).json()

def test_preview_then_batch_deduplicates_seed_and_plan(tmp_path):
 with TestClient(create_app(tmp_path)) as c:
  p=make(c,301);q=make(c,302)
  body=dict(seeds=[301,301],plan_hashes=[p['plan_hash'],q['plan_hash']])
  preview=c.post('/api/lifecycle/batch-delete',json=body).json()
  assert preview['counts']['ready']==2
  assert len(c.get('/api/plans').json())==2
  result=c.post('/api/lifecycle/batch-delete',json={**body,'dry_run':False}).json()
  assert result['counts']['deleted']==2 and len(result['items'])==2
  assert c.get('/api/plans').json()==[]
  assert len(list((tmp_path/'trash/plans').iterdir()))==2

def test_batch_keeps_queued_plan_and_reports_unknown(tmp_path):
 with TestClient(create_app(tmp_path)) as c:
  p=make(c,301);q=make(c,302)
  c.post('/api/jobs',json=dict(run=dict(plan_hash=p['plan_hash']),scheduled_at=time.time()+3600))
  body=dict(plan_hashes=[p['plan_hash'],q['plan_hash']],run_ids=['missing'],dry_run=False)
  result=c.post('/api/lifecycle/batch-delete',json=body).json()
  assert result['counts']==dict(ready=0,deleted=1,blocked=1,error=1)
  assert [x['plan_hash'] for x in c.get('/api/plans').json()]==[p['plan_hash']]

def test_batch_run_history_and_preserved_embedded_plan(tmp_path):
 with TestClient(create_app(tmp_path)) as c:
  p=make(c,303);ids=[]
  for i in range(2):
   r=c.post('/api/runs',json=dict(plan_hash=p['plan_hash'],speed=100)).json();ids.append(r['id'])
   for _ in range(100):
    if c.get('/api/runs/'+r['id']).json()['status']=='completed' and c.app.state.manager.tasks[r['id']].done():break
    time.sleep(.02)
  result=c.post('/api/lifecycle/batch-delete',json=dict(run_ids=[ids[0],ids[0]],seeds=[303],dry_run=False)).json()
  assert result['counts']['deleted']==2
  assert [r['id'] for r in c.get('/api/runs').json()]==[ids[1]]
  assert c.get('/api/runs/'+ids[1]+'/ground-truth').status_code==200

def test_batch_auth_and_empty_request(tmp_path):
 with TestClient(create_app(tmp_path,token='secret')) as c:
  assert c.post('/api/lifecycle/batch-delete',json={}).status_code==401
  assert c.post('/api/lifecycle/batch-delete',json={},headers={'Authorization':'Bearer secret'}).status_code==400
