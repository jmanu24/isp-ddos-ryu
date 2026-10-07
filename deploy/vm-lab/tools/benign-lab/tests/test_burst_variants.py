import copy,json,hashlib
from pathlib import Path
from fastapi.testclient import TestClient
import yaml
from benign_lab.config import ROOT
from benign_lab.planner import generate,load_profiles,canonical,validate
from benign_lab.burst_variants import duration_variant
from benign_lab.api import create_app

def test_duration_variants_preserve_quotas_protocols_and_parent():
 p=generate(load_profiles(ROOT/'profiles'),1,30);before=canonical(p)
 for floor in (1,2):
  q=duration_variant(p,floor);validate(q);assert q['plan_hash']!=p['plan_hash'] and q['parent_plan_hash']==p['plan_hash']
  assert canonical(q)==canonical(duration_variant(p,floor))
  old={e['event_id']:e for e in p['events']}
  for e in q['events']:
   original=old[e['event_id']];assert e['planned_bytes']==original['planned_bytes']
   assert 0<=e['start_s'] and e['start_s']+e['duration_s']<=q['duration_s']+.000001
   if original['wire_protocol'] not in ('tcp','http') or e['event_id'] in q['retained_short_event_ids']:assert e==original
   elif original['duration_s']<floor:assert e['duration_s']==floor and e['rate_bps']<=original['rate_bps']+.1
  for domain,value in q['summary'].items():assert value['peak_load']<=q['profiles']['common']['domains'][domain]['benign_peak_load']+.000001
 assert canonical(p)==before

def test_pilot_api_preserves_original_files_and_builds_balanced_order(tmp_path):
 source=Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/data/plans');hashes=['2c3580be4272c69a94c0ee39a990b0d33b9aa8654f60ab35d120283d2e118245','18aa3c08e732aa6ac773f09538ccabe6df629ee3effb8d02b0d191f2538dbd1c','aace0dfc7bc48ca29417b543acc1b6e3c8c40c3ba34644f834b8f11179a8b948'];plans=tmp_path/'plans';plans.mkdir();original={}
 for h in hashes:
  data=(source/(h+'.json')).read_bytes();(plans/(h+'.json')).write_bytes(data);original[h]=data
 cfg=yaml.safe_load((ROOT/'config/lab.demo.yaml').read_text());cfg['capacity_mbps']=json.loads(original[hashes[0]])['capacity_mbps'];path=tmp_path/'lab.yaml';path.write_text(yaml.safe_dump(cfg));app=create_app(tmp_path,path);app.state.experiment_jobs.launch=lambda:None
 with TestClient(app) as c:
  assert c.post('/api/burst-pilot/start',json={}).status_code==400
  response=c.post('/api/burst-pilot/prepare',json={});assert response.status_code==200,response.text;pilot=response.json();assert len(pilot['steps'])==9
  assert [(x['seed'],x['minimum_s']) for x in pilot['labels']]==[(1,0),(1,1),(1,2),(2,1),(2,2),(2,0),(3,2),(3,0),(3,1)]
  assert all(x['execution_profile']=='persistent' and x['pipeline']=='baseline' for x in pilot['steps'])
  job=c.post('/api/burst-pilot/start',json={});assert job.status_code==200 and job.json()['kind']=='burst_duration_pilot'
  assert c.post('/api/burst-pilot/start',json={}).status_code==400
  c.post('/api/jobs/'+job.json()['id']+'/cancel',json={})
 for h,data in original.items():assert (plans/(h+'.json')).read_bytes()==data
