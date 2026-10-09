import copy,json
import pytest
from benign_lab.config import ROOT,load_lab,resolve,peering_assignments
from benign_lab.planner import generate,load_profiles,canonical

def test_assignment_balances_logical_sources_without_mutating_plan():
 cfg=load_lab(ROOT/'config/lab.connected.yaml');cfg['peering_pool']=dict(strategy='logical_source_round_robin_v1',members=['peer-router','peer-router-2']);p=generate(load_profiles(ROOT/'profiles'),1,600,cfg['capacity_mbps']);before=canonical(p)
 mapping=peering_assignments(cfg,p);assert set(mapping.values())=={'peer-router','peer-router-2'}
 counts=[sum(v==n for v in mapping.values()) for n in cfg['peering_pool']['members']];assert abs(counts[0]-counts[1])<=1
 reverse=copy.deepcopy(p);reverse['events'].reverse();assert peering_assignments(cfg,reverse)==mapping
 groups=resolve(cfg,p);peer=[g for g in groups.values() if g['context']['domain']=='peering'];assert len(peer)==2
 assert {g['context']['source_as'] for g in peer}=={64512,64513}
 for group in peer:
  for event in group['events']:assert mapping[event['source']]==group['context']['executor_name']
 assert canonical(p)==before

def test_bad_pool_rejected(tmp_path):
 cfg=load_lab(ROOT/'config/lab.connected.yaml');cfg['peering_pool']=dict(strategy='logical_source_round_robin_v1',members=['peer-router','peer-router-2']);p={'events':[]};cfg['peering_pool']['members']=['peer-router','peer-router']
 with pytest.raises(ValueError):peering_assignments(cfg,p)

def test_old_config_without_pool_retains_single_executor():
 cfg=load_lab(ROOT/'config/lab.connected.yaml');cfg.pop('peering_pool',None);p=generate(load_profiles(ROOT/'profiles'),1,600,cfg['capacity_mbps'])
 groups=resolve(cfg,p);assert len([g for g in groups.values() if g['context']['domain']=='peering'])==1
