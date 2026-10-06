import io,json,zipfile,math
from pathlib import Path
from types import SimpleNamespace
import pytest
from benign_lab.experimental_analytics import ExperimentalAnalytics,seed_statistics
from benign_lab.planner import generate,load_profiles
from benign_lab.config import ROOT

def manager(tmp_path):
 root=tmp_path/'runs';root.mkdir();m=SimpleNamespace(runs={},events={},folder=lambda rid:root/rid);return m

def record(m,rid,seed=1,delivery=.9,pipeline='baseline',status='completed',capacity=100):
 p=generate(load_profiles(ROOT/'profiles'),seed,5,{d:capacity for d in ('mobile','fixed','enterprise','peering')});folder=m.folder(rid);folder.mkdir()
 r=dict(id=rid,status=status,mode='lab',purpose='baseline_plan',scenario='B0',pipeline=pipeline,seed=seed,plan_hash=p['plan_hash'],execution_hash='exec',execution_profile='coordinated',duration_s=5,elapsed_s=5,created_at=100,started_at=100,finished_at=105,agents={},observed_attacks=[],attack_windows=[],experiment_context={'schema':1,'captured_at':seed,'transport':{'transport':'wired'}})
 es={e['event_id']:dict(e,status='completed',bytes_tx=int(e['planned_bytes']*delivery),bytes_rx=0,lateness_s=.01) for e in p['events']}
 (folder/'run.json').write_text(json.dumps(r));(folder/'benign_plan.json').write_text(json.dumps(p));(folder/'event_states.json').write_text(json.dumps(es));(folder/'lab_snapshot.json').write_text(json.dumps({'nodes':{},'targets':{}}))
 m.runs[rid]=r;m.events[rid]=es;return folder

def test_seed_balancing_and_no_pseudoreplication():
 s=seed_statistics([(1,80),(1,100),(2,70)]);assert s['n_runs']==3;assert s['n_seeds']==2;assert s['seed_balanced']['mean']==80;assert s['run_weighted']['mean']==pytest.approx(83.3333333)
 assert s['ci95']['df']==1
 assert seed_statistics([(1,80),(1,100)])['ci95'] is None
 assert seed_statistics([(1,100),(2,100)])['ci95'] is None

def test_known_t_interval():
 s=seed_statistics([(1,90),(2,95),(3,100)]);assert s['seed_balanced']['sd']==5;assert s['ci95']['half_width']==pytest.approx(4.303*5/math.sqrt(3))

def test_cohorts_separate_pipeline_capacity_and_aborted(tmp_path):
 m=manager(tmp_path);record(m,'baseline',1,pipeline='baseline');record(m,'enabled',1,pipeline='enabled');record(m,'capacity',2,capacity=200);record(m,'failed',2,status='failed');m.runs['failed']['started_at']=None;m.runs['failed']['elapsed_s']=0
 a=ExperimentalAnalytics(tmp_path,m);r=a.report(list(m.runs));assert len(r['groups'])==3;assert r['excluded'][0]['id']=='failed';assert len(r['pairs'])==1
 assert r['pairs'][0]['context_verified'] is False

def test_repeats_same_seed_not_more_independent_seeds(tmp_path):
 m=manager(tmp_path);record(m,'a',1);record(m,'b',1,delivery=.8);record(m,'c',2,delivery=.7)
 r=ExperimentalAnalytics(tmp_path,m).report(['a','b','c']);assert len(r['groups'])==1;assert r['groups'][0]['statistics']['n_seeds']==2

def test_same_plan_paired_seed_deltas(tmp_path):
 m=manager(tmp_path)
 for seed in [1,2]:record(m,'b'+str(seed),seed,delivery=.95,pipeline='baseline');record(m,'e'+str(seed),seed,delivery=.65,pipeline='enabled')
 r=ExperimentalAnalytics(tmp_path,m).report(list(m.runs));assert len(r['group_comparisons'])==1;comparison=r['group_comparisons'][0];assert comparison['statistics']['n_seeds']==2;assert comparison['statistics']['seed_balanced']['mean']==pytest.approx(-30,abs=.1)

def test_no_fp_evidence_is_missing_not_zero(tmp_path):
 m=manager(tmp_path);record(m,'old');d=ExperimentalAnalytics(tmp_path,m).detail('old');assert all(x['detection_fpr_pct'] is None for x in d['metrics']);assert d['evaluation']['available'] is False

def test_import_deduplicates_existing_run_and_rejects_paths(tmp_path):
 m=manager(tmp_path);folder=record(m,'existing');a=ExperimentalAnalytics(tmp_path,m)
 def archive(paths):
  buffer=io.BytesIO()
  with zipfile.ZipFile(buffer,'w') as z:
   for name,path in paths:z.writestr(name,path.read_bytes())
  return buffer.getvalue()
 raw=archive([(p.name,p) for p in folder.iterdir()]);assert a.import_archive(raw)['duplicate'] is True
 bad=archive([('../run.json',folder/'run.json')])
 with pytest.raises(ValueError,match='flat'):a.import_archive(bad)


def test_tampered_plan_and_negative_counters_excluded(tmp_path):
 m=manager(tmp_path);folder=record(m,'bad');first=next(iter(m.events['bad'].values()));first['bytes_tx']=-1
 a=ExperimentalAnalytics(tmp_path,m);assert 'invalid_counters' in a.summary('bad')['exclusion_reasons']


def test_api_analytics_auth_and_active_guard(tmp_path):
 from fastapi.testclient import TestClient
 from benign_lab.api import create_app
 app=create_app(data_dir=tmp_path,lab_path=ROOT/'config/lab.demo.yaml',token='test')
 with TestClient(app) as client:
  assert client.get('/api/analytics/catalog').status_code==401
  assert client.get('/api/analytics/catalog',headers={'Authorization':'Bearer test'}).json()['counts']['total']==0
  app.state.manager.runs['active']={'status':'running'}
  result=client.post('/api/analytics/report',headers={'Authorization':'Bearer test'},json={'run_ids':['active']});assert result.status_code==409;app.state.manager.runs.pop('active')
