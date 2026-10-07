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

def test_retired_pilot_cannot_create_variants_or_jobs(tmp_path):
 cfg=yaml.safe_load((ROOT/'config/lab.demo.yaml').read_text());path=tmp_path/'lab.yaml';path.write_text(yaml.safe_dump(cfg));app=create_app(tmp_path,path)
 plans=tmp_path/'plans';original=plans/'retained.json';original.write_text('{"retained": true}')
 before=original.read_bytes()
 with TestClient(app) as c:
  for endpoint in ('prepare','start'):
   response=c.post('/api/burst-pilot/'+endpoint,json={})
   assert response.status_code==409 and 'BENIGN_V1' in response.json()['detail']
  assert c.get('/api/jobs').json()==[]
 assert original.read_bytes()==before and len(list(plans.glob('*.json')))==1
