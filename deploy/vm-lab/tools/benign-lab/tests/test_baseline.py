import asyncio,json
import pytest
from benign_lab.runner import Manager
from benign_lab.config import ROOT,load_lab
from benign_lab.planner import generate,load_profiles,save_plan

@pytest.mark.parametrize('mode,scenario',[('simulation','B0'),('lab','B0+attack')])
def test_baseline_rejects_wrong_scenarios(tmp_path,mode,scenario):
 p=generate(load_profiles(ROOT/'profiles'),1,5);f=save_plan(p,tmp_path/'p.json')
 with pytest.raises(ValueError,match='Baseline requires'):
  asyncio.run(Manager(tmp_path/'runs').start(p,f,load_lab(ROOT/'config/lab.demo.yaml'),mode=mode,scenario=scenario,speed=1,pipeline='baseline'))

def test_baseline_restores_after_failed_preparation(tmp_path,monkeypatch):
 import benign_lab.runner as runner
 flags=[]
 class Guard:
  def __init__(self,*args):pass
  async def enter(self):flags.append('enter');raise RuntimeError('preflight failed')
  async def leave(self):flags.append('leave');return dict(restored=True)
 monkeypatch.setattr(runner,'BaselineGuard',Guard)
 async def run():
  p=generate(load_profiles(ROOT/'profiles'),1,5);f=save_plan(p,tmp_path/'p.json');cfg=load_lab(ROOT/'config/lab.demo.yaml');cfg['baseline_control']={}
  cfg['baseline_control']['configured']=True
  m=Manager(tmp_path/'runs');r=await m.start(p,f,cfg,mode='lab',speed=1,pipeline='baseline');await m.tasks[r['id']]
  assert m.runs[r['id']]['status']=='failed'
  assert m.runs[r['id']]['baseline_control']['restoration']['restored']
  assert (m.folder(r['id'])/'benign_plan.json').read_bytes()==f.read_bytes()
 asyncio.run(run());assert flags==['enter','leave']

@pytest.mark.parametrize('outcome',['complete','stop','monitor_error'])
def test_baseline_restores_after_all_exit_paths(tmp_path,monkeypatch,outcome):
 import benign_lab.runner as runner
 flags=[]
 class Guard:
  def __init__(self,*args):pass
  async def enter(self):return dict(active=True)
  async def leave(self):flags.append('restored');return dict(restored=True)
  async def monitor(self):
   if outcome=='monitor_error':
    await asyncio.sleep(.01);raise RuntimeError('suspension lost')
   await asyncio.Event().wait()
 monkeypatch.setattr(runner,'BaselineGuard',Guard)
 async def real(self,rid,*args):
  self.runs[rid]['status']='running'
  if outcome=='complete':
   for e in self.events[rid].values():e['status']='completed'
  elif outcome=='stop':
   await self.stop(rid)
  else:await asyncio.Event().wait()
 monkeypatch.setattr(runner.Manager,'real',real)
 async def run():
  p=generate(load_profiles(ROOT/'profiles'),1,5);f=save_plan(p,tmp_path/'plan.json');cfg=load_lab(ROOT/'config/lab.demo.yaml');cfg['baseline_control']={'configured':True}
  m=Manager(tmp_path/'runs');r=await m.start(p,f,cfg,mode='lab',speed=1,pipeline='baseline');await asyncio.wait_for(m.tasks[r['id']],2)
  assert m.runs[r['id']]['status']=={'complete':'completed','stop':'stopped','monitor_error':'failed'}[outcome]
  assert m.runs[r['id']]['baseline_control']['restoration']['restored']
 asyncio.run(run());assert flags==['restored']
