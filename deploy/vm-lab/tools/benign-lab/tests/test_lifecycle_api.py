import time
import hashlib
import json
from fastapi.testclient import TestClient
from benign_lab.api import create_app

def plan(c,seed=91):
    r=c.post('/api/plans',json=dict(seed=seed,duration_s=5,capacity_mbps=dict.fromkeys(['mobile','fixed','enterprise','peering'],10)))
    assert r.status_code==200,r.text
    return r.json()

def wait_job(c,jid):
    for _ in range(200):
        j=next(x for x in c.get('/api/jobs').json() if x['id']==jid)
        if j['status'] in ('completed','failed','attention','cancelled'):return j
        time.sleep(.05)
    raise AssertionError(j)

def test_series_and_delete_seed_preserves_run_evidence(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        p=plan(c);ph=p['plan_hash'];raw=c.get('/api/plans/'+ph+'/download').content
        response=c.post('/api/jobs',json=dict(run=dict(plan_hash=ph,mode='simulation',speed=100),count=2))
        assert response.status_code==200,response.text
        job=wait_job(c,response.json()['id']);assert job['status']=='completed',job
        assert len(job['run_ids'])==2 and len(set(job['run_ids']))==2
        for rid in job['run_ids']:
            assert (tmp_path/'runs'/rid/'benign_plan.json').read_bytes()==raw
            r=c.get('/api/runs/'+rid).json();assert r['series_id']==job['id'] and r['seed']==91
        assert c.delete('/api/seeds/91').status_code==200
        assert c.get('/api/plans').json()==[]
        assert c.get('/api/plans/'+ph).json()['plan_hash']==ph
        for rid in job['run_ids']:
            assert c.get('/api/runs/'+rid+'/ground-truth').status_code==200
            assert c.get('/api/runs/'+rid+'/export').status_code==200
        assert c.post('/api/jobs',json=dict(run=dict(plan_hash=ph))).status_code==404
        rid=job['run_ids'][0]
        assert c.delete('/api/runs/'+rid).json()['recoverable']
        assert c.get('/api/runs/'+rid).status_code==404
        assert rid not in [x['id'] for x in c.get('/api/analytics/catalog').json()['items']]
        assert list((tmp_path/'trash/runs').glob('*/run.json'))
    recovered=create_app(tmp_path)
    assert len(recovered.state.manager.runs)==1

def test_future_plan_protection_cancel_and_validation(tmp_path):
    with TestClient(create_app(tmp_path,token='secret')) as c:
        assert c.delete('/api/seeds/1').status_code==401
        c.headers['Authorization']='Bearer secret'
        p=plan(c);body=dict(run=dict(plan_hash=p['plan_hash']),count=3,scheduled_at=time.time()+3600)
        r=c.post('/api/jobs',json=body);assert r.status_code==200
        assert c.delete('/api/plans/'+p['plan_hash']).status_code==409
        assert c.delete('/api/seeds/91').status_code==409
        assert c.post('/api/jobs',json={**body,'count':101}).status_code==422
        assert c.post('/api/jobs',json={**body,'run':{**body['run'],'scenario':'B0+attack'}}).status_code==400
        assert c.post('/api/jobs/'+r.json()['id']+'/cancel',json={}).status_code==200
        assert c.delete('/api/plans/'+p['plan_hash']).status_code==200

def test_active_run_cannot_be_deleted(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        p=plan(c);r=c.post('/api/runs',json=dict(plan_hash=p['plan_hash'],speed=.1)).json()
        assert c.delete('/api/runs/'+r['id']).status_code==409
        assert c.delete('/api/seeds/91').status_code==409
        c.post('/api/runs/'+r['id']+'/stop',json={})
