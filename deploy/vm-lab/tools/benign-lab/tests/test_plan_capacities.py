import copy,io,json,zipfile
import pytest
from fastapi.testclient import TestClient
from benign_lab.config import ROOT,load_lab,resolve
from benign_lab.planner import generate,load_profiles,canonical
from benign_lab.api import create_app
from test_api import wait_done

CUSTOM={'mobile':10,'fixed':300,'enterprise':600,'peering':150}

def test_custom_capacity_real_mapping_preflight_preserves_configuration_and_plan():
 cfg=load_lab(ROOT/'config/lab.connected.yaml');plan=generate(load_profiles(ROOT/'profiles'),1,600,CUSTOM)
 before_cfg=canonical(cfg);before_plan=canonical(plan)
 groups=resolve(cfg,plan)
 assert groups and sum(len(g['events']) for g in groups.values())==len(plan['events'])
 assert canonical(cfg)==before_cfg and canonical(plan)==before_plan

def test_optional_strict_capacity_policy_rejects_difference():
 cfg=load_lab(ROOT/'config/lab.connected.yaml');cfg['require_matching_plan_capacities']=True
 plan=generate(load_profiles(ROOT/'profiles'),1,600,CUSTOM)
 with pytest.raises(ValueError,match='Strict capacity policy'):resolve(cfg,plan)

def test_custom_capacities_do_not_bypass_missing_mapping():
 cfg=load_lab(ROOT/'config/lab.connected.yaml');cfg['nodes']['ue1']['configured']=False
 plan=generate(load_profiles(ROOT/'profiles'),1,600,CUSTOM)
 with pytest.raises(ValueError,match='Incomplete laboratory mapping'):resolve(cfg,plan)

def test_paired_custom_plan_exports_both_capacity_references(tmp_path):
 cfg=load_lab(ROOT/'config/lab.demo.yaml');reference=copy.deepcopy(cfg['capacity_mbps'])
 with TestClient(create_app(tmp_path,ROOT/'config/lab.demo.yaml')) as c:
  response=c.post('/api/plans',json=dict(seed=1,duration_s=5,capacity_mbps=CUSTOM));assert response.status_code==200,response.text
  plan=response.json();ph=plan['plan_hash'];original=c.get('/api/plans/'+ph+'/download').content;records=[]
  for scenario in ['B0','B0+attack']:
   response=c.post('/api/runs',json=dict(plan_hash=ph,mode='simulation',scenario=scenario,speed=100,attack_windows=[] if scenario=='B0' else [dict(name='test',start_s=1,end_s=2)]));assert response.status_code==200,response.text
   r=wait_done(c,response.json()['id']);assert r['status']=='completed',r
   assert r['plan_capacity_mbps']==CUSTOM and r['lab_reference_capacity_mbps']==reference and r['capacities_differ']
   with zipfile.ZipFile(io.BytesIO(c.get('/api/runs/'+r['id']+'/export').content)) as z:
    assert z.read('benign_plan.json')==original
    assert json.loads(z.read('lab_snapshot.json'))['capacity_mbps']==reference
    assert json.loads(z.read('run.json'))['plan_capacity_mbps']==CUSTOM
   records.append(r)
  assert records[0]['plan_file_sha256']==records[1]['plan_file_sha256']
  assert records[0]['execution_hash']==records[1]['execution_hash']
  assert c.get('/api/config').json()['lab']['capacity_mbps']==reference
