import copy,asyncio,time
from pathlib import Path
import pytest
from benign_lab.config import ROOT,load_lab,resolve,supervisor_groups
from benign_lab.planner import generate,load_profiles,plan_hash,summarize,save_plan,canonical
from benign_lab.runner import Manager
from benign_lab.agent import receive_client
from benign_lab.execution import execution_options


def test_partition_preserves_plan_and_logical_sources():
    cfg=load_lab(ROOT/'config/lab.demo.yaml');cfg['execution']={'peering_workers':2}
    plan=generate(load_profiles(ROOT/'profiles'),1,600);before=canonical(plan)
    groups=resolve(cfg,plan);peer=[g for g in groups.values() if g['context']['domain']=='peering']
    assert len(peer)==2
    assert not peer[0]['sources'].intersection(peer[1]['sources'])
    expected={e['event_id']:e for e in plan['events'] if e['domain']=='peering'}
    actual={e['event_id']:e for g in peer for e in g['events']}
    assert actual==expected and sum(len(g['events']) for g in peer)==len(expected)
    assert canonical(plan)==before
    def assignment(groups):return {source:g['context']['worker_shard'] for g in groups.values() if g['context']['domain']=='peering' for source in g['sources']}
    reverse=copy.deepcopy(plan);reverse['events'].reverse()
    assert assignment(resolve(cfg,reverse))==assignment(groups)
    loads=[sum(e['planned_bytes'] for e in g['events']) for g in peer]
    largest=max(sum(e['planned_bytes'] for e in expected.values() if e['source']==s) for s in set(e['source'] for e in expected.values()))
    assert abs(loads[0]-loads[1])<=largest
    assert len(supervisor_groups(groups))==1

@pytest.mark.parametrize('value',[0,17,1.5,True,'2'])
def test_reject_invalid_worker_count(value):
    with pytest.raises(ValueError):execution_options({'execution':{'peering_workers':value}})

@pytest.mark.skipif(__import__('sys').platform=='win32',reason='Linux process and pipe integration')
@pytest.mark.parametrize('profile',['coordinated','persistent'])
def test_two_peering_processes_share_supervisor_and_preserve_payload(tmp_path,profile):
    async def run():
        server=await asyncio.start_server(receive_client,'127.0.0.1',0);port=server.sockets[0].getsockname()[1]
        cfg=load_lab(ROOT/'config/lab.demo.yaml');cfg['execution']={'peering_workers':2};cfg['start_lead_s']=.2
        cfg['targets']['victim-web'].update(tcp_port=port,http_port=port)
        plan=generate(load_profiles(ROOT/'profiles'),7,5);prototype=plan['events'][0];plan['events']=[]
        for source in ('peer-flow1','peer-flow2'):
            for repeat in range(2):
                plan['events'].append(dict(prototype,event_id=source+'-'+str(repeat),domain='peering',source=source,protocol='tcp',wire_protocol='tcp',direction='ul',start_s=.2+repeat*2,duration_s=1,rate_bps=9600,rate_fraction=.000096,planned_bytes=1200,packet_size_bytes=200))
        plan['summary']=summarize(plan);plan['plan_hash']=plan_hash(plan);path=save_plan(plan,tmp_path/'plan.json');manager=Manager(tmp_path/'runs')
        try:
            r=await manager.start(plan,path,cfg,mode='lab',speed=1,execution_profile=profile);await asyncio.wait_for(manager.tasks[r['id']],15);result=manager.snapshot(r['id'])
            assert result['status']=='completed',result
            assert result['execution_transport']['sessions']==1 and result['execution_transport']['workers']==2
            assert result['counts']=={'completed':4} and result['bytes_tx']==4800
            assert len({a['pid'] for a in result['agents'].values()})==2
            assert (manager.folder(r['id'])/'benign_plan.json').read_bytes()==path.read_bytes()
        finally:await manager.shutdown();server.close();await server.wait_closed()
    asyncio.run(run())
