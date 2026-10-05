import asyncio,copy
import pytest
from benign_lab.baseline import BaselineGuard

@pytest.mark.parametrize('namespace',['fixed3',''])
def test_fixed_refresh_discovers_current_address_without_pipeline_change(monkeypatch,namespace):
 cfg={'baseline_control':{'fixed_host':'subscriber','fixed_user':'labadmin','bng_host':'bng','bng_user':'labadmin'},'nodes':{'fixed3':{'access_mode':'ipoe_namespace','namespace':namespace,'interface':'macvlan3','source_ip':'10.20.0.163','session_id':'ipoe2'}}}
 g=BaselineGuard(cfg,'test',5);calls=[]
 async def ssh(host,user,command,**kwargs):
  calls.append((host,command));assert host=='bng'
  return 'ipoe3 | ens192 | 02:00:00:00:00:03 | 10.20.0.39 | ipoe | | active | 00:01:00\n'
 async def addresses():return [{'namespace':namespace,'ifname':'macvlan3','addr_info':[{'family':'inet','local':'10.20.0.39'}]}]
 async def sleep(*args):pass
 g.ssh=ssh;g.fixed_addresses=addresses;monkeypatch.setattr(asyncio,'sleep',sleep)
 result=asyncio.run(g.prepare_fixed())
 assert cfg['nodes']['fixed3']['source_ip']=='10.20.0.39'
 assert cfg['nodes']['fixed3']['session_id']=='ipoe3'
 assert result['mapping']['fixed3']['namespace']==namespace
 assert len(calls)==3


def test_fixed_rejects_wrong_namespace_without_overwriting_mapping(monkeypatch):
 cfg={'baseline_control':{'fixed_host':'subscriber','fixed_user':'labadmin','bng_host':'bng','bng_user':'labadmin'},'nodes':{'fixed3':{'access_mode':'ipoe_namespace','namespace':'fixed3','interface':'macvlan3','source_ip':'10.20.0.163'}}}
 g=BaselineGuard(cfg,'test',5)
 async def ssh(*args,**kwargs):return 'ipoe3 | ens192 | MAC | 10.20.0.39 | ipoe | | active | 00:01:00\n'
 async def addresses():return [{'namespace':'fixed4','ifname':'macvlan3','addr_info':[{'family':'inet','local':'10.20.0.39'}]}]
 async def sleep(*args):pass
 g.ssh=ssh;g.fixed_addresses=addresses;monkeypatch.setattr(asyncio,'sleep',sleep)
 with pytest.raises(RuntimeError,match='stable namespace IPs'):asyncio.run(g.prepare_fixed())
 assert cfg['nodes']['fixed3']['source_ip']=='10.20.0.163'

@pytest.mark.parametrize('scenario',['B0','B0+attack'])
def test_enabled_runner_refreshes_before_agents_without_entering_baseline(tmp_path,monkeypatch,scenario):
 import benign_lab.runner as runner
 from benign_lab.config import ROOT,load_lab
 from benign_lab.planner import generate,load_profiles,save_plan
 flags=[]
 class Guard:
  def __init__(self,cfg,*args):self.cfg=cfg
  async def prepare_fixed(self,reconnect=False):
   assert not reconnect;flags.append('refresh');self.cfg['nodes']['fixed1']['source_ip']='10.20.0.39';return {'mapping':{'fixed1':{'source_ip':'10.20.0.39'}}}
  async def enter(self):raise AssertionError('Pipeline must remain enabled')
 monkeypatch.setattr(runner,'BaselineGuard',Guard)
 async def real(self,rid,plan,cfg,groups):
  flags.append('agents');assert cfg['nodes']['fixed1']['source_ip']=='10.20.0.39'
  for e in self.events[rid].values():e['status']='completed'
 monkeypatch.setattr(runner.Manager,'real',real)
 async def run():
  cfg=load_lab(ROOT/'config/lab.demo.yaml');cfg['nodes']['fixed1']=dict(cfg['nodes']['fixed*']);cfg['nodes']['fixed1'].update(access_mode='ipoe_namespace',namespace='fixed1',interface='macvlan1',source_ip='10.20.0.163');cfg['baseline_control']={}
  p=generate(load_profiles(ROOT/'profiles'),1,5);f=save_plan(p,tmp_path/'plan.json');before=f.read_bytes();m=runner.Manager(tmp_path/'runs')
  r=await m.start(p,f,cfg,mode='lab',scenario=scenario,speed=1,pipeline='enabled');await m.tasks[r['id']]
  assert m.runs[r['id']]['status']=='completed',m.runs[r['id']].get('error')
  assert m.runs[r['id']]['baseline_control']=={}
  assert cfg['nodes']['fixed1']['source_ip']=='10.20.0.163'
  assert f.read_bytes()==before
 asyncio.run(run());assert flags==['refresh','agents']

