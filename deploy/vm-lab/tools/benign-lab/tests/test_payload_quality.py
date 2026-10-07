import asyncio,time,sys
from unittest.mock import patch
import pytest
from benign_lab import agent


def test_budget_uses_last_packet_schedule_without_rate_increase():
 e=dict(planned_bytes=4096,packet_size_bytes=1200,rate_bps=32768,direction='ul',wire_protocol='tcp')
 m={'event_start_monotonic':99.9}
 with patch('benign_lab.agent.time.monotonic',return_value=100):agent.payload_budget(e,m,100.9)
 assert m['required_payload_s']==pytest.approx(3600/4096)
 assert m['nominal_payload_s']==1 and m['budget_shortfall_s']==0
 assert m['setup_consumed_s']==pytest.approx(.1) and e['rate_bps']==32768
 with patch('benign_lab.agent.time.monotonic',return_value=100):agent.payload_budget(e,m,100.5)
 assert m['budget_shortfall_s']==pytest.approx(3600/4096-.5)


def test_quota_state_is_separate_from_receiver_confirmation():
 e={'wire_protocol':'tcp','planned_bytes':100}
 assert agent.payload_outcome(e,{'bytes_tx':30,'bytes_rx':0})=='partial'
 assert agent.payload_outcome(e,{'bytes_tx':100,'bytes_rx':0})=='full_local'
 assert agent.payload_outcome(e,{'bytes_tx':0,'bytes_rx':0})=='zero'
 assert agent.payload_outcome({'wire_protocol':'icmp','planned_bytes':100},{'icmp_replies':1})=='not_applicable'


def test_tcp_dl_complete_records_phases_and_observed_receipt():
 async def run():
  server=await asyncio.start_server(agent.receive_client,'127.0.0.1',0)
  try:
   e=dict(planned_bytes=1200,packet_size_bytes=200,rate_bps=96000,wire_protocol='tcp',direction='dl')
   m=dict(bytes_tx=0,bytes_rx=0,chunks_tx=0,chunks_rx=0,event_start_monotonic=time.monotonic())
   await agent.traffic(e,{'host':'127.0.0.1','tcp_port':server.sockets[0].getsockname()[1]},m,time.monotonic()+1)
   assert m['receiver_bytes']==1200 and m['receiver_confirmation']=='client_received'
   assert m['connect_start_monotonic']<=m['connect_end_monotonic']<=m['request_sent_monotonic']<=m['first_payload_monotonic']<=m['last_payload_monotonic']
  finally:server.close();await server.wait_closed()
 asyncio.run(run())

async def _worker_event(e):
 import json,sys
 from benign_lab.config import ROOT
 server=await asyncio.start_server(agent.receive_client,'127.0.0.1',0)
 proc=None
 try:
  target={'host':'127.0.0.1','tcp_port':server.sockets[0].getsockname()[1]}
  proc=await asyncio.create_subprocess_exec(sys.executable,str(ROOT/'benign_lab/agent.py'),'worker',stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
  proc.stdin.write((json.dumps({'events':[e],'targets':{'victim-web':target},'duration_s':2})+'\n').encode());await proc.stdin.drain()
  ready=json.loads(await asyncio.wait_for(proc.stdout.readline(),5));assert ready['type']=='ready'
  proc.stdin.write((json.dumps({'start_unix':time.time()+.1})+'\n').encode());await proc.stdin.drain()
  raw=await asyncio.wait_for(proc.stdout.read(),5);await proc.wait()
  rows=[json.loads(x) for x in raw.splitlines()]
  return next(x for x in rows if x.get('type')=='event' and x.get('status') not in ('running','pending'))
 finally:
  server.close();await server.wait_closed()
  if proc and proc.returncode is None:proc.kill();await proc.wait()


@pytest.mark.skipif(sys.platform=='win32',reason='Linux worker stdin/namespace integration')
def test_real_worker_marks_partial_payload_failed():
 e=dict(event_id='partial',start_s=0,duration_s=.2,planned_bytes=1200,rate_bps=800,packet_size_bytes=200,wire_protocol='tcp',direction='ul',destination='victim-web')
 result=asyncio.run(_worker_event(e))
 assert result['status']=='failed' and result['payload_state']=='partial'
 assert result['bytes_tx']==200 and result['shortfall_bytes']==1000
 assert result['receiver_confirmation']=='unverified' and result['connect_s']>=0


@pytest.mark.skipif(sys.platform=='win32',reason='Linux worker ping integration')
def test_icmp_worker_is_not_application_payload_quota():
 e=dict(event_id='ping',start_s=0,duration_s=1,planned_bytes=56,rate_bps=448,packet_size_bytes=56,wire_protocol='icmp',direction='ul',destination='victim-web')
 result=asyncio.run(_worker_event(e))
 assert result['status']=='completed' and result['icmp_replies']==1
 assert result['payload_state']=='not_applicable' and result['shortfall_bytes']==0
