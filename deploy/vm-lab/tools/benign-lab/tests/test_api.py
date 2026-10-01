import io
import json
import time
import zipfile
from fastapi.testclient import TestClient
from benign_lab.api import create_app
from benign_lab.config import ROOT
from benign_lab.runner import Manager


def wait_done(client,rid):
    for _ in range(1500):
        r=client.get('/api/runs/'+rid).json()
        if r['status'] in ('completed','completed_with_errors','failed','stopped'): return r
        time.sleep(.02)
    raise AssertionError('Experiment did not terminate')


def test_paired_baseline_exports_and_restart(tmp_path):
    app=create_app(tmp_path,ROOT/'config/lab.demo.yaml')
    with TestClient(app) as c:
        response=c.post('/api/plans',json=dict(seed=1,duration_s=600,capacity_mbps=dict.fromkeys(['mobile','fixed','enterprise','peering'],100)))
        assert response.status_code==200,response.text
        p=response.json()
        ph=p['plan_hash']
        assert c.post(f'/api/plans/{ph}/preflight',json={}).status_code==200
        original=c.get(f'/api/plans/{ph}/download').content
        result=[]
        for scenario in ('B0','B0+attack'):
            response=c.post('/api/runs',json=dict(plan_hash=ph,scenario=scenario,speed=100,attack_windows=[] if scenario=='B0' else [dict(name='x',start_s=300,end_s=360)]))
            assert response.status_code==200,response.text
            rid=response.json()['id']
            r=wait_done(c,rid)
            assert r['status']=='completed',r
            assert r['counts']=={'completed':len(p['events'])},r['counts']
            assert r['bytes_tx']+r['bytes_rx']==sum(e['planned_bytes'] for e in p['events'])
            result.append(r)
            z=zipfile.ZipFile(io.BytesIO(c.get(f'/api/runs/{rid}/export').content))
            assert z.read('benign_plan.json')==original
            assert 'ground_truth_windows.csv' in z.namelist()
            assert 'generated_events.csv' in z.namelist()
        assert result[0]['plan_hash']==result[1]['plan_hash']==ph
        assert result[0]['plan_file_sha256']==result[1]['plan_file_sha256']
        rows=c.get('/api/runs/'+result[1]['id']+'/ground-truth').json()
        assert rows[60]['label']=='UNKNOWN' and rows[0]['label']=='BENIGN'
    recovered=Manager(tmp_path/'runs')
    assert len(recovered.runs)==2


def test_auth_cross_origin_and_invalid_inputs(tmp_path):
    with TestClient(create_app(tmp_path,token='testsecret')) as c:
        assert c.get('/api/config').status_code==401
        headers={'Authorization':'Bearer testsecret'}
        assert c.get('/api/config',headers=headers).status_code==200
        assert c.post('/api/plans',headers={**headers,'Origin':'https://other.example'},json={}).status_code==403
        assert c.post('/api/plans/import',headers=headers,json={'plan_hash':'bad'}).status_code==400
        assert c.get('/api/plans/not-a-hash',headers=headers).status_code==400


def test_stop_and_concurrent_run_rejected(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        response=c.post('/api/plans',json=dict(seed=1,duration_s=30,capacity_mbps=dict.fromkeys(['mobile','fixed','enterprise','peering'],100)))
        assert response.status_code==200,response.text
        ph=response.json()['plan_hash']
        body=dict(plan_hash=ph,mode='simulation',speed=1)
        r=c.post('/api/runs',json=body).json()
        assert c.post('/api/runs',json=body).status_code==400
        assert c.post('/api/runs/'+r['id']+'/stop',json={}).status_code==200
        done=wait_done(c,r['id'])
        assert done['status']=='stopped'
        assert done['elapsed_s']<30
        assert any(e['status']=='cancelled' for e in c.get('/api/runs/'+r['id']+'/events').json()['items'])
