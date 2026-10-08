import asyncio,collections
import pytest
from benign_lab.scenario_series import scenario_steps,SCENARIOS
from benign_lab.detection_evaluation import evaluate
from test_detection_evaluation import dataset
from test_experiment_jobs import setup

def references():return [dict(plan_hash=str(seed),scenario='B0',pipeline='baseline',mode='lab',execution_profile='classic',speed=1,attack_windows=[]) for seed in (1,2,3,2,3,1,3,1,2,1,3,2,3,2,1,2,1,3)]
@pytest.mark.parametrize('scenario',list(SCENARIOS))
def test_four_scenarios_keep_plan_order_and_quotas(scenario):
 ref=references();steps,ips=scenario_steps(ref,scenario,300,360,['10.30.0.2'],'UDP lab 60 s')
 assert len(steps)==18 and collections.Counter(x['plan_hash'] for x in steps)=={'1':6,'2':6,'3':6}
 assert [x['plan_hash'] for x in steps]==[x['plan_hash'] for x in ref]
 assert all(x['execution_profile']=='classic' and (x['scenario'],x['pipeline'])==SCENARIOS[scenario] for x in steps)
 assert all(x['pipeline']=='baseline' for x in ref)
 assert bool(steps[0]['attack_windows'])==scenario.startswith('attack_')

def test_attack_requires_repeatable_conditions_and_window():
 with pytest.raises(ValueError):scenario_steps(references(),'attack_on')
 with pytest.raises(ValueError):scenario_steps(references(),'attack_on',360,300,['10.30.0.2'],'UDP')
 with pytest.raises(ValueError):scenario_steps(references(),'attack_on',300,360,['8.8.8.8'],'UDP')

@pytest.mark.parametrize('confirmed',[True,False])
def test_manual_series_waits_or_stops_without_confirmation(tmp_path,confirmed):
 async def run():
  q,m,p=setup(tmp_path);old=m.start
  async def start(request):
   result=await old(request)
   if confirmed:m.runs[result['id']]['observed_attacks']=[dict(start_s=1,end_s=2)]
   return result
  q.start=start;req=dict(plan_hash='x',pipeline='enabled');job=q.create(req,2,60,steps=[req,req],kind='scenario_series');j=q.jobs[job['id']];j.update(manual_attack=True,experimental_scenario='attack_on')
  await q.tick();assert len(m.started)==1
  if confirmed:
   assert j['status']=='awaiting_operator';await q.tick();assert len(m.started)==1
   q.continue_manual(j['id']);assert j['status']=='pending';j['next_at']=0;await q.tick();assert j['status']=='completed'
  else:assert j['status']=='attention' and 'confirmado' in j['error']
 asyncio.run(run())

@pytest.mark.parametrize('detected,label',[(True,'VP'),(False,'FN')])
def test_confirmed_attack_confusion_requires_coverage(detected,label):
 p,r,a,i,e=dataset(detected=detected);r.update(scenario='B0+attack',observed_attacks=[dict(name='external_attack',start_s=0,end_s=5)],attack_source_ips=['10.20.0.36'])
 x=evaluate(p,r,a,i,e)['confusion_matrix'];assert x['counts'][label]==1 and x['counts']['VN']==1
 r['pipeline']='baseline';x=evaluate(p,r,a,i,e)['confusion_matrix'];assert x['counts']['unknown']==2 and x['counts'][label]==0
 r['pipeline']='enabled';r['attack_source_ips']=['10.99.0.1'];x=evaluate(p,r,a,i,e)['confusion_matrix'];assert x['counts']['unknown']==1 and x['counts']['FN']==0

def test_benign_confusion_and_absent_coverage():
 x=evaluate(*dataset())['confusion_matrix'];assert x['counts']['FP']==1 and x['counts']['VN']==1
 x=evaluate(*dataset(covered=False))['confusion_matrix'];assert x['counts']['unknown']==2 and x['counts']['VN']==0

def test_series_api_matches_selection_and_no_duplicate(tmp_path):
 import shutil
 from pathlib import Path
 from fastapi.testclient import TestClient
 from benign_lab.api import create_app
 from benign_lab.config import ROOT
 plans=tmp_path/'plans';plans.mkdir();source=Path('/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab/data/plans')
 for ph in ['2c3580be4272c69a94c0ee39a990b0d33b9aa8654f60ab35d120283d2e118245','18aa3c08e732aa6ac773f09538ccabe6df629ee3effb8d02b0d191f2538dbd1c','aace0dfc7bc48ca29417b543acc1b6e3c8c40c3ba34644f834b8f11179a8b948']:shutil.copyfile(source/(ph+'.json'),plans/(ph+'.json'))
 app=create_app(tmp_path,ROOT/'config/lab.connected.yaml');app.state.experiment_jobs.launch=lambda:None
 with TestClient(app) as c:
  for scenario in SCENARIOS:
   body=dict(scenario=scenario,start_s=300,end_s=360,source_ips=['10.30.0.2'],description='UDP lab 60 s')
   preview=c.post('/api/scenario-series/preview',json=body);assert preview.status_code==200,preview.text
   assert len(preview.json()['steps'])==18 and all(s['pipeline']==SCENARIOS[scenario][1] for s in preview.json()['steps'])
   j=c.post('/api/scenario-series/start',json=body);assert j.status_code==200,j.text;assert j.json()['experimental_scenario']==scenario
   assert c.post('/api/scenario-series/start',json=body).status_code==400
   assert c.post('/api/jobs/'+j.json()['id']+'/cancel',json={}).status_code==200
