import asyncio,copy,io,json,zipfile
import pytest
from fastapi.testclient import TestClient
from benign_lab.config import ROOT,load_lab,resolve
from benign_lab.planner import generate,generate_benchmark,load_profiles,canonical,plan_hash,validate,summarize
from benign_lab.api import create_app
from benign_lab.baseline import BaselineGuard
from test_api import wait_done

@pytest.mark.parametrize('domain',['mobile','fixed','enterprise','peering'])
def test_benchmark_retains_exact_domain_events_and_reproducibility(domain):
 profiles=load_profiles(ROOT/'profiles');full=generate(profiles,1,600)
 plan=generate_benchmark(profiles,1,600,None,domain)
 assert plan['events']==[e for e in full['events'] if e['domain']==domain]
 assert plan['parent_plan_hash']==full['plan_hash'] and plan['plan_hash']!=full['plan_hash']
 assert canonical(plan)==canonical(generate_benchmark(profiles,1,600,None,domain))
 cfg=load_lab(ROOT/'config/lab.connected.yaml');groups=resolve(cfg,plan)
 assert all(g['context']['domain']==domain for g in groups.values())
 assert len(groups)=={'mobile':5,'fixed':10,'enterprise':5,'peering':1}[domain]

def test_benchmark_rejects_mixed_import_even_with_recomputed_hash():
 profiles=load_profiles(ROOT/'profiles');p=generate_benchmark(profiles,1,5,None,'mobile');full=generate(profiles,1,5)
 p['events'].append(next(e for e in full['events'] if e['domain']=='enterprise'));p['summary']=summarize(p);p['plan_hash']=plan_hash(p)
 with pytest.raises(ValueError,match='exactly'):validate(p)

@pytest.mark.parametrize('domain',['peering','enterprise','mobile'])
def test_baseline_skips_inactive_domain_requirements_and_valid_guest_payload(domain):
 cfg=load_lab(ROOT/'config/lab.connected.yaml');guard=BaselineGuard(cfg,'benchmark-test',5);guard.domains={domain};calls=[]
 async def controller(code):
  compile(code,'guest','exec');calls.append(code)
  return json.dumps({'expires_at':9999999999} if len(calls)==1 else {'enforced':{}})
 async def status():return dict(active=True,cleared=True,run_id='benchmark-test')
 async def ssh(host,user,command,**kwargs):
  assert command in ('ovs-ofctl -O OpenFlow13 dump-flows br-ent','systemctl show ryu-manager -p Environment');return ''
 async def fixed():raise AssertionError('Inactive Fixed must not be accessed')
 guard.controller=controller;guard.status=status;guard.ssh=ssh;guard.fixed_addresses=fixed
 result=asyncio.run(guard.enter());assert result['fixed_sessions'] is None
 assert len(calls)==(2 if domain=='mobile' else 1)

def test_api_benchmark_export_and_mode_contract(tmp_path):
 with TestClient(create_app(tmp_path,ROOT/'config/lab.demo.yaml')) as c:
  assert c.post('/api/plans',json={'benchmark_domain':'invalid'}).status_code==422
  p=c.post('/api/plans',json=dict(benchmark_domain='fixed',seed=1,duration_s=5)).json();ph=p['plan_hash'];original=c.get('/api/plans/'+ph+'/download').content
  assert c.post('/api/runs',json=dict(plan_hash=ph,mode='lab',speed=1,pipeline='enabled')).status_code==400
  assert c.post('/api/runs',json=dict(plan_hash=ph,scenario='B0+attack')).status_code==400
  r=c.post('/api/runs',json=dict(plan_hash=ph,mode='simulation',speed=100)).json();r=wait_done(c,r['id'])
  assert r['status']=='completed' and r['benchmark_metrics']['observed_pct']==100
  with zipfile.ZipFile(io.BytesIO(c.get('/api/runs/'+r['id']+'/export').content)) as z:
   assert z.read('benign_plan.json')==original
   summary=json.loads(z.read('benchmark_summary.json'));assert summary['domain']=='fixed' and summary['observed_pct']==100
   es=json.loads(z.read('event_states.json')).values();assert all(e['domain']=='fixed' for e in es)
  assert next(x for x in c.get('/api/plans').json() if x['plan_hash']==ph)['benchmark_domain']=='fixed'


def test_fixed_benchmark_refresh_payload_and_session_mapping():
 cfg=load_lab(ROOT/'config/lab.connected.yaml');guard=BaselineGuard(cfg,'fixed-benchmark-test',5);guard.domains={'fixed'}
 nodes=[(name,n) for name,n in cfg['nodes'].items() if n.get('access_mode') in ('ipoe_bound','ipoe_namespace')]
 addresses=[dict(ifname=n['interface'],namespace=n.get('namespace',''),addr_info=[dict(family='inet',local=n['source_ip'])]) for _,n in nodes]
 sessions='\n'.join('ipoe'+str(i)+' | user | mac | '+n['source_ip']+' | ipoe | | active | 1' for i,(_,n) in enumerate(nodes))
 async def controller(code):compile(code,'guest','exec');return json.dumps({'expires_at':9999999999})
 async def status():return dict(active=True,cleared=True,run_id='fixed-benchmark-test')
 async def fixed():return addresses
 async def ssh(host,user,command,**kwargs):
  if command=='python3 -':compile(kwargs['payload'],'refresh-guest','exec');return ''
  return '' if command.startswith('ovs-ofctl') else sessions
 guard.controller=controller;guard.status=status;guard.ssh=ssh;guard.fixed_addresses=fixed
 result=asyncio.run(guard.enter());assert result['mobile'] is None and result['fixed_sessions']==sessions
 assert all(n['session_id'].startswith('ipoe') for _,n in nodes)
