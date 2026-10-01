import asyncio
import copy
import json
import time
import sys
import pytest
from benign_lab.agent import receive_client,UDPReceiver
from benign_lab.config import ROOT,load_lab
from benign_lab.planner import generate,load_profiles,plan_hash,save_plan,summarize
from benign_lab.runner import Manager


@pytest.mark.skipif(sys.platform=='win32', reason='Local laboratory worker requires Linux/POSIX')
def test_real_runner_payload_and_persisted_result(tmp_path):
    async def scenario():
        receiver=await asyncio.start_server(receive_client,'127.0.0.1',0)
        port=receiver.sockets[0].getsockname()[1]
        udp,_=await asyncio.get_running_loop().create_datagram_endpoint(UDPReceiver,local_addr=('127.0.0.1',0))
        uport=udp.get_extra_info('sockname')[1]
        cfg=load_lab(ROOT/'config/lab.demo.yaml')
        cfg['start_lead_s']=.1
        cfg['targets']['victim-web'].update(tcp_port=port,http_port=port,udp_port=uport)
        plan=generate(load_profiles(ROOT/'profiles'),7,5)
        prototype=plan['events'][0]
        plan['events']=[]
        for i,(proto,direction) in enumerate((('tcp','ul'),('tcp','dl'),('http','ul'),('http','dl'),('udp','ul'),('udp','dl'))):
            e=dict(prototype,event_id=f'mobile-test{i}',domain='mobile',source='ue1',destination='victim-web',
                   protocol=proto,wire_protocol=proto,direction=direction,start_s=.2,duration_s=.5,
                   rate_bps=19200,rate_fraction=.000192,planned_bytes=1200,packet_size_bytes=200)
            plan['events'].append(e)
        plan['summary']=summarize(plan)
        plan['plan_hash']=plan_hash(plan)
        path=save_plan(plan,tmp_path/'plan.json')
        manager=Manager(tmp_path/'runs')
        try:
            r=await manager.start(plan,path,cfg,mode='lab',speed=1)
            await asyncio.wait_for(manager.tasks[r['id']],15)
            result=manager.snapshot(r['id'])
            assert result['status']=='completed',result
            assert result['bytes_tx']==3600 and result['bytes_rx']==3600
            assert result['elapsed_s']==5
            assert (manager.folder(r['id'])/'benign_plan.json').read_bytes()==path.read_bytes()
            assert all(e['lateness_s'] is not None and e['src_port'] for e in manager.events[r['id']].values())
        finally:
            await manager.shutdown()
            receiver.close()
            await receiver.wait_closed()
            udp.close()
    asyncio.run(scenario())


def test_recovery_marks_pending_events_interrupted(tmp_path):
    p=generate(load_profiles(ROOT/'profiles'),7,5)
    folder=tmp_path/'recover'
    folder.mkdir()
    save_plan(p,folder/'benign_plan.json')
    (folder/'run.json').write_text(json.dumps(dict(id='recover',status='running',elapsed_s=2,attack_windows=[],observed_attacks=[])))
    (folder/'event_states.json').write_text(json.dumps({'a':dict(event_id='a',status='running')}))
    m=Manager(tmp_path)
    assert m.runs['recover']['status']=='interrupted'
    assert m.events['recover']['a']['status']=='interrupted'


def test_csv_union_of_protocol_specific_fields():
    from benign_lab.runner import csv_text
    import csv,io
    rows=list(csv.DictReader(io.StringIO(csv_text([{'id':'peer','protocol':'udp'},{'id':'mobile','protocol':'tcp','parent_event':17}]))))
    assert rows[0]['parent_event']==''
    assert rows[1]['parent_event']=='17'
