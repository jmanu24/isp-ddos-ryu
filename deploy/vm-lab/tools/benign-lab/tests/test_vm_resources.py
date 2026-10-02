import time,io,json,zipfile,os
import pytest
from benign_lab.resource_probe import difference
from benign_lab.vm_resources import ready_sample

def test_guest_cpu_and_pid_reuse_and_disk_rates():
 p=dict(pid=12,start_ticks=1,ppid=1,name='worker',ticks=10,rss_bytes=4096,read_bytes=100,write_bytes=None,namespace='fixed1')
 old=dict(mono=1,cpu=[10,0,10,80,0,0,0,0],processes={(12,1):p},disks={'sda':dict(read_bytes=512,write_bytes=0,io_ms=100,reads=1,writes=0)})
 new=dict(old,mono=3,timestamp=time.time(),logical_cpus=2,cpu=[20,0,20,160,0,0,0,0],memory={'MemTotal':10000,'MemAvailable':4000},load=[1,1,1],processes={(12,1):dict(p,ticks=10+os.sysconf('SC_CLK_TCK')*2,read_bytes=300),(13,2):dict(p,pid=13)},disks={'sda':dict(read_bytes=1536,write_bytes=1024,io_ms=1100,reads=3,writes=2)})
 r=difference(old,new);assert r['cpu_pct']==20;assert r['memory_pct']==60;assert len(r['processes'])==1;assert r['processes'][0]['cpu_pct']==100;assert r['processes'][0]['read_bytes_per_s']==100;assert r['processes'][0]['write_bytes_per_s'] is None;assert r['disks'][0]['busy_pct']==50
 # A reused PID has no delta against the former process.
 new['processes']={(12,99):dict(p,start_ticks=99)};assert not difference(old,new)['processes']

def test_ready_normalized_by_vcpu():
 p={'sample':[{'sampleInfo':[{'timestamp':'2026-10-02T23:00:00Z','interval':20}],'value':[{'name':'cpu.usage.average','instance':'','value':[4000]},{'name':'cpu.ready.summation','instance':'','value':[8000]},{'name':'cpu.ready.summation','instance':'0','value':[1000]}]}]}
 r=ready_sample(p,dict(name='du',vcpus=8));assert r['ready_vcpu_pct']==5;assert r['ready_per_vcpu_pct']['0']==5
 with pytest.raises(ValueError):ready_sample(p,dict(name='du',vcpus=0))

def test_vm_export_and_empty_old_run(tmp_path):
 from fastapi.testclient import TestClient
 from benign_lab.api import create_app
 from benign_lab.config import ROOT
 app=create_app(tmp_path,ROOT/'config/lab.demo.yaml',token='')
 with TestClient(app) as c:
  now=time.time();app.state.vm_resources.accept({'name':'node','domain':'fixed'},{'timestamp':now,'cpu_pct':30,'interval_s':5,'metrics_kind':'guest_resources'})
  assert c.get('/api/vm-resources').json()['items'][0]['metrics_kind']=='guest_resources'
  m=app.state.manager;rid='vm-export';m.folder(rid).mkdir(parents=True);m.runs[rid]={'id':rid,'mode':'lab','started_at':now-1,'finished_at':now+1,'status':'completed','duration_s':1};m.persist=lambda rid:None
  assert c.get('/api/runs/'+rid+'/vm-resources').json()['items'][0]['cpu_pct']==30
  z=zipfile.ZipFile(io.BytesIO(c.get('/api/runs/'+rid+'/export').content));assert 'vm_resources.jsonl' in z.namelist()
  assert c.get('/api/runs/missing/vm-resources').status_code==404
