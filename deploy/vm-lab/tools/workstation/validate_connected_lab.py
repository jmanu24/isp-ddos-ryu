import sys,os,json,asyncio,hashlib
from pathlib import Path
repo=Path(__file__).resolve().parents[4];app=repo/'deploy/vm-lab/tools/benign-lab';private=repo/'.runtime/benign-lab';sys.path.insert(0,str(app));sys.path.insert(0,str(repo/'deploy/vm-lab'))
from benign_lab.config import load_lab
from benign_lab.planner import generate,load_profiles,plan_hash,summarize,save_plan
from benign_lab.runner import Manager
from webtool.inventory import credentials_for
os.environ['BENIGN_SSH_PASSWORD']=json.loads((private/'ssh.json').read_text())['password'];os.environ['BENIGN_PE_SSH_PASSWORD']=credentials_for('pe')[1]
cfg=load_lab(app/'config/lab.connected.yaml');scientific=private/'data/plans/2c3580be4272c69a94c0ee39a990b0d33b9aa8654f60ab35d120283d2e118245.json';before=hashlib.sha256(scientific.read_bytes()).hexdigest()
p=generate(load_profiles(app/'profiles'),1,8,cfg['capacity_mbps']);prototype=p['events'][0];p['events']=[]
sources=[('mobile','ue'+str(i)) for i in range(1,6)]+[('fixed','fixed'+str(i)) for i in range(1,11)]+[('enterprise','ent-site-'+str(i)) for i in range(1,6)]+[('peering','peer-flow1')]
for domain,source in sources:
 for index,(proto,direction) in enumerate((('tcp','ul'),('tcp','dl'),('http','ul'),('http','dl'),('udp','ul'),('udp','dl'))):
  p['events'].append(dict(prototype,event_id='migration-'+source+'-'+str(index),domain=domain,source=source,destination='victim-web',protocol=proto,wire_protocol=proto,direction=direction,start_s=.2,duration_s=6,rate_bps=1600,rate_fraction=1600/(cfg['capacity_mbps'][domain]*1e6),planned_bytes=1200,packet_size_bytes=1200))
p['purpose']='Post-migration low-volume connectivity smoke test; separate from scientific baseline';p['summary']=summarize(p);p['plan_hash']=plan_hash(p);path=save_plan(p,private/'migration'/('smoke-'+p['plan_hash']+'.json'))
async def test():
 m=Manager(private/'migration/smoke-runs')
 try:
  r=await m.start(p,path,cfg,mode='lab',speed=1,pipeline='baseline');print('Connectivity smoke preparing '+r['id'],flush=True)
  await asyncio.wait_for(m.tasks[r['id']],240)
  result=m.snapshot(r['id']);events=list(m.events[r['id']].values());failed=[{'event':e['event_id'],'error':e.get('error'),'status':e['status']} for e in events if e['status']!='completed']
  report={'run_id':r['id'],'purpose':p['purpose'],'status':result['status'],'error':result.get('error'),'agents':len(result.get('agents',{})),'events':len(events),'counts':result['counts'],'bytes_tx':result['bytes_tx'],'bytes_rx':result['bytes_rx'],'domains':result['domains'],'failed':failed,'baseline_control':result.get('baseline_control'),'original_plan_sha256':hashlib.sha256(scientific.read_bytes()).hexdigest()}
  (private/'migration/smoke-validation.json').write_text(json.dumps(report,indent=2));print(json.dumps({k:v for k,v in report.items() if k not in ['baseline_control','domains']}),flush=True)
  assert report['original_plan_sha256']==before
  assert result['status']=='completed',result.get('error')
  assert not failed,failed
  assert result['baseline_control']['restoration']['restored']
 finally:await m.shutdown()
asyncio.run(test())
