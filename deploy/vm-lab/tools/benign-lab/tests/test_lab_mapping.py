import asyncio
import copy
import time
import pytest
from benign_lab import agent
from benign_lab.config import ROOT, command, executor_for, load_lab, mapping_issues, resolve
from benign_lab.planner import generate,load_profiles


def node(**kw):
    return dict(configured=True,adapter='ssh',host='10.0.0.2',user='lab',source_ip='10.2.0.2',interface='eth1',**kw)


def test_real_inventory_requires_explicit_values_and_not_sample_ips():
    cfg=load_lab(ROOT/'config/lab.real.yaml')
    assert cfg['targets']['victim-web']['host']=='10.55.0.100'
    assert cfg['nodes']['ue1']['namespace']=='ue1'
    assert cfg['nodes']['fixed1']['host'] is None
    assert 'capacity_mbps.fixed' in mapping_issues(cfg)
    with pytest.raises(ValueError,match='Complete and enable'):
        executor_for(cfg,dict(domain='mobile',source='ue1'))


def test_domain_contracts_and_ipoe_alternatives():
    cfg=dict(require_explicit_mapping=True,nodes={'fixed1':node(access_mode='ipoe_bound',session_id='subscriber-session-1')})
    e=dict(domain='fixed',source='fixed1')
    assert executor_for(cfg,e)['check_route']
    cfg['nodes']['fixed1'].update(adapter='ssh_netns',namespace='subscriber1',access_mode='ipoe_namespace')
    assert 'ip netns exec subscriber1' in command(executor_for(cfg,e))[-1]
    cfg['nodes']['fixed1']['session_id']=None
    with pytest.raises(ValueError,match='session_id'): executor_for(cfg,e)
    cfg['nodes']={'ue1':node()}
    with pytest.raises(ValueError,match='UE namespace'): executor_for(cfg,dict(domain='mobile',source='ue1'))
    cfg['nodes']={'peer-flow*':node()}
    with pytest.raises(ValueError,match='peer-router'): executor_for(cfg,dict(domain='peering',source='peer-flow8'))


def test_fixed_bound_ips_get_distinct_workers_and_peering_aggregates():
    cfg=load_lab(ROOT/'config/lab.demo.yaml')
    p=generate(load_profiles(ROOT/'profiles'),1,5)
    a=next(e for e in p['events'] if e['domain']=='fixed')
    p['events']=[dict(a,source='fixed1'),dict(a,source='fixed2')]
    cfg['nodes']={'fixed1':node(), 'fixed2':{**node(),'source_ip':'10.2.0.3'}}
    assert len(resolve(cfg,p))==2
    p['events']=[dict(a,domain='peering',source='peer-flow1'),dict(a,domain='peering',source='peer-flow50')]
    cfg['nodes']={'peer-flow*':node(expected_gateway='10.2.0.1')}
    assert len(resolve(cfg,p))==1


def test_route_evidence_rejects_management_path_and_wrong_peer(monkeypatch):
    context=dict(check_route=True,source_ip='10.2.0.2',interface='eth1',expected_gateway='10.2.0.1')
    route={'dev':'eth1','gateway':'10.2.0.1'}
    async def fake(*args):
        if args[0]=='address': return [dict(addr_info=[dict(local='10.2.0.2')])]
        return [route.copy()]
    monkeypatch.setattr(agent,'ip_json',fake)
    def inspect(): return asyncio.run(agent.inspect_context(context,{'v':dict(host='10.55.0.100')},[dict(destination='v')]))
    assert inspect()['route_checked']
    route['dev']='mgmt0'
    with pytest.raises(ValueError,match='interface'): inspect()
    route.update(dev='eth1',gateway='10.0.0.1')
    with pytest.raises(ValueError,match='gateway'): inspect()


def test_bound_source_real_tcp_http_udp_upload_and_download():
    async def run():
        server=await asyncio.start_server(agent.receive_client,'127.0.0.1',0)
        port=server.sockets[0].getsockname()[1]
        udp,_=await asyncio.get_running_loop().create_datagram_endpoint(agent.UDPReceiver,local_addr=('127.0.0.1',0))
        target=dict(host='127.0.0.1',tcp_port=port,http_port=port,udp_port=udp.get_extra_info('sockname')[1])
        try:
            for proto in ('tcp','http','udp'):
                for direction in ('ul','dl'):
                    event=dict(planned_bytes=1200,rate_bps=96000,packet_size_bytes=200,wire_protocol=proto,direction=direction)
                    m=dict(bytes_tx=0,bytes_rx=0,chunks_tx=0,chunks_rx=0)
                    await asyncio.wait_for(agent.traffic(event,target,m,time.monotonic()+1,dict(source_ip='127.0.0.1')),2)
                    assert m['bytes_tx' if direction=='ul' else 'bytes_rx']==1200
                    assert m['source_ip']=='127.0.0.1'
        finally:
            udp.close()
            server.close()
            await server.wait_closed()
    asyncio.run(run())


def test_real_mapping_api_lists_missing_parameters(tmp_path):
    from fastapi.testclient import TestClient
    from benign_lab.api import create_app
    with TestClient(create_app(tmp_path,ROOT/'config/lab.real.yaml')) as c:
        assert c.get('/api/config').json()['mapping_issues']
        assert c.post('/api/plans',json=dict(seed=1,duration_s=5)).status_code==400
