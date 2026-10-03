import pytest,time
from benign_lab.host_monitor import HostMonitor,esxi_sample

def test_esxi_aggregate_not_sum_of_logical_cpus():
 p={'sample':[{'sampleInfo':[{'timestamp':'2026-10-02T23:00:00Z','interval':20}],'value':[{'name':'cpu.usage.average','instance':'','value':[4596]},{'name':'cpu.usage.average','instance':'0','value':[2532]},{'name':'cpu.usage.average','instance':'1','value':[-1]}]}]}
 row=esxi_sample(p,'ESXi');assert row['cpu_pct']==45.96;assert row['per_cpu_pct']=={'0':25.32};assert row['interval_s']==20

def test_duplicate_samples_history_and_validation(tmp_path):
 m=HostMonitor(tmp_path,{'host_monitor':{'hosts':[{'name':'host'}]}});n={'name':'host'}
 row={'timestamp':time.time(),'cpu_pct':22.5,'interval_s':5}
 m.accept(n,row);m.accept(n,row);assert len(m.response()['items'])==1;assert m.response()['hosts'][0]['status']=='connected'
 assert not m.rows(0,time.time()+1,after=m.response()['cursor'])
 with pytest.raises(ValueError):m.accept(n,dict(row,cpu_pct=101))
 m.db.close()

def test_resource_api_and_export(tmp_path):
 import io,json,zipfile
 from fastapi.testclient import TestClient
 from benign_lab.api import create_app
 from benign_lab.config import ROOT
 app=create_app(tmp_path,ROOT/'config/lab.demo.yaml',token='')
 with TestClient(app) as c:
  now=time.time();app.state.host_monitor.accept({'name':'test-host'},{'timestamp':now,'cpu_pct':20,'interval_s':5})
  assert c.get('/api/resources').json()['items'][0]['cpu_pct']==20
  manager=app.state.manager;rid='export-test';manager.folder(rid).mkdir(parents=True)
  manager.runs[rid]={'id':rid,'mode':'lab','started_at':now-1,'finished_at':now+1,'status':'completed','duration_s':1}
  async def persist_mock(rid,after=None):
   return after() if after else None
  manager.persist_async=persist_mock
  assert c.get('/api/runs/'+rid+'/resources').json()['items'][0]['cpu_pct']==20
  z=zipfile.ZipFile(io.BytesIO(c.get('/api/runs/'+rid+'/export').content));assert json.loads(z.read('host_metrics.jsonl'))['cpu_pct']==20
  assert c.get('/api/runs/missing/resources').status_code==404
