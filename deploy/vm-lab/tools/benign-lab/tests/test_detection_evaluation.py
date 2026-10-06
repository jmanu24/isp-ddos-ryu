import asyncio,json,logging,math
from pathlib import Path
import pytest
from benign_lab.detection_evaluation import evaluate,calibration
from benign_lab.threshold_control import ThresholdControl

def dataset(seed=1,covered=True,detected=True):
 p={'duration_s':10,'warmup_s':0,'seed':seed,'plan_hash':'test','ground_truth':{'window_s':5},'events':[{'domain':'fixed','source':'fixed1'}]}
 r={'id':'synthetic','mode':'lab','status':'completed','scenario':'B0','pipeline':'enabled','started_at':100,'elapsed_s':10,'duration_s':10,'finished_at':110,'attack_windows':[],'observed_attacks':[],'_lab':{'nodes':{'fixed1':{'source_ip':'10.20.0.36','access_mode':'ipoe_namespace','namespace':'fixed1','interface':'macvlan1'}},'targets':{}},'agents':{}}
 records=[]
 if covered:records=[{'kind':'cycle','timestamp':101,'pipeline_active':True,'observed_sources':{'broadband':['10.20.0.36']},'active_blocks':{},'thresholds':{'values':{'SYN_THRESHOLD':10,'DECISION_THRESHOLD':1.5}}},{'kind':'cycle','timestamp':106,'pipeline_active':True,'observed_sources':{'broadband':['10.20.0.36']},'active_blocks':{},'thresholds':{'values':{'SYN_THRESHOLD':10,'DECISION_THRESHOLD':1.5}}}]
 if detected:
  d={'domain':'broadband','src_ip':'10.20.0.36','sources':[]}
  records += [{'kind':'detection','event_id':'d','timestamp':102,'detection':d},{'kind':'decision','timestamp':102,'accepted':True,'threshold':1.5,'candidates':[{'detection':d,'effective_score':2}]}]
 return p,r,records,[],[]

def test_missing_coverage_never_becomes_tn():
 x=evaluate(*dataset(covered=False,detected=False));d=x['domains'][0];assert d['eligible_benign_windows']==0;assert d['detection_fpr'] is None;assert d['detection_tn']==0

def test_fp_denominator_alias_and_replay():
 x=evaluate(*dataset());d=x['domains'][0];assert d['eligible_benign_windows']==2;assert d['detection_fp']==1;assert d['detection_tn']==1;assert d['detection_fpr']==.5
 x=evaluate(*dataset(),decision_threshold=3);assert x['domains'][0]['decision_fp']==0;assert x['domains'][0]['detection_fp']==1

def test_unknown_sources_are_not_experiment_fp():
 p,r,a,i,e=dataset();a[2]['detection']['src_ip']='10.99.0.1';x=evaluate(p,r,a,i,e);assert x['domains'][0]['detection_fp']==0;assert x['unattributed_detection_records']==1

def test_warmup_and_unobserved_truth_excluded():
 p,r,a,i,e=dataset();p['warmup_s']=5;x=evaluate(p,r,a,i,e);assert x['domains'][0]['eligible_benign_windows']==1;assert x['domains'][0]['detection_fp']==0
 r['elapsed_s']=4;r['status']='failed';x=evaluate(p,r,a,i,e);assert x['domains'][0]['eligible_benign_windows']==0

def test_ip_change_is_temporal_evidence():
 p,r,a,i,e=dataset();a.append({'event_id':'issued','timestamp':102,'kind':'mitigation_issued','action':{'domain':'broadband','src_ip':'10.20.0.36'}});i=[{'timestamp':104,'namespace':'fixed1','interface':'macvlan1','ipv4_known':True,'ipv4_addresses':[]}]
 x=evaluate(p,r,a,i,e);assert x['ip_changes'][0]['nearby_mitigation_ids']==['issued'];assert x['ip_changes'][0]['association']=='temporal_only'

def test_calibration_requires_independent_seeds_and_positive_thresholds():
 data={'a':dataset(1),'b':dataset(2)};assert calibration(data,['a'],['b'],[1.5,3])['recommended_threshold'] is None
 x=calibration(data,['a'],['b'],[1.5,3],minimum_windows=1,minimum_per_domain=1);assert x['results'][0]['validation'] is None;assert x['recommended_threshold']==3;assert x['results'][1]['validation']['decision_fpr']==0
 with pytest.raises(ValueError):calibration(data,['a'],['a'],[1.5])
 data['b']=dataset(1)
 with pytest.raises(ValueError,match='independent seeds'):calibration(data,['a'],['b'],[1.5])

@pytest.mark.parametrize('value',[0,-1,float('nan'),float('inf'),True])
def test_invalid_threshold_never_calls_remote(value):
 c=ThresholdControl({'baseline_control':{}})
 with pytest.raises(ValueError):asyncio.run(c.apply({'DECISION_THRESHOLD':value},'hash'))

def test_threshold_writer_changes_only_allowed_assignment(tmp_path,monkeypatch):
 import subprocess,socket,time,hashlib
 cfg=tmp_path/'settings.py';cfg.write_text('DECISION_THRESHOLD = 1.5\nSYN_THRESHOLD = 10\nUDP_THRESHOLD = 200\nICMP_THRESHOLD = 150\nKEEP = 7\n')
 c=ThresholdControl({'baseline_control':{'host':'orch','user':'labadmin'}})
 async def fake(*args,**kwargs):
  code=kwargs['payload'].replace('/opt/Tesis_Controller/config/settings.py',str(cfg)).replace('/var/lib/benign-threshold-history',str(tmp_path/'history')).replace('/run/benign-baseline/lease.json',str(tmp_path/'lease.json'))
  import contextlib,io
  out=io.StringIO()
  with contextlib.redirect_stdout(out):exec(code,{})
  return out.getvalue()
 c.guard.ssh=fake
 monkeypatch.setattr(subprocess,'run',lambda *args,**kwargs:None);monkeypatch.setattr(time,'sleep',lambda _:None)
 class Socket:
  def close(self):pass
 monkeypatch.setattr(socket,'create_connection',lambda *args,**kwargs:Socket())
 digest=hashlib.sha256(cfg.read_bytes()).hexdigest();result=asyncio.run(c.apply({'DECISION_THRESHOLD':2.5},digest));assert result['applied']['DECISION_THRESHOLD']==2.5;assert 'DECISION_THRESHOLD = 2.5' in cfg.read_text();assert 'KEEP = 7' in cfg.read_text()


def test_api_rejects_threshold_change_during_run(tmp_path):
 from fastapi.testclient import TestClient
 from benign_lab.api import create_app
 from benign_lab.config import ROOT
 app=create_app(data_dir=tmp_path,lab_path=ROOT/'config/lab.demo.yaml',token='test')
 app.state.manager.runs['active']={'status':'running'}
 with TestClient(app) as client:
  app.state.manager.runs['active']={'status':'running'}
  result=client.post('/api/calibration/thresholds',json={'values':{'DECISION_THRESHOLD':2},'expected_hash':'hash'},headers={'Authorization':'Bearer test'});assert result.status_code==409
  app.state.manager.runs.pop('active')


def test_decision_attributed_only_to_winning_candidate():
 p,r,a,i,e=dataset();a[-1]['candidates'].append({'detection':{'domain':'enterprise','src_ip':'10.70.0.99'},'effective_score':4})
 x=evaluate(p,r,a,i,e);assert x['domains'][0]['detection_fp']==1;assert x['domains'][0]['decision_fp']==0

def test_mixed_detector_configuration_rejected():
 data={'a':dataset(1),'b':dataset(2)};data['b'][2][0]['thresholds']['values']['SYN_THRESHOLD']=20
 with pytest.raises(ValueError,match='same detector configuration'):calibration(data,['a'],['b'],[1.5,3])
