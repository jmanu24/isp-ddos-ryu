import asyncio,time,sys,json,os,threading
from pathlib import Path
import pytest
from benign_lab.agent import receive_client,traffic
from benign_lab.connection_pool import ConnectionPool
from benign_lab.execution import execution_options
from benign_lab.config import ROOT,load_lab,supervisor_groups,resolve
from benign_lab.planner import generate,load_profiles,plan_hash,save_plan,summarize,canonical
from benign_lab.runner import Manager
from benign_lab.transport import SupervisorSession


def event(proto='tcp',direction='dl',size=1200):
    return dict(source='fixed1',application='bulk',wire_protocol=proto,direction=direction,planned_bytes=size,rate_bps=19200,packet_size_bytes=200)
def counters():return dict(bytes_tx=0,bytes_rx=0,chunks_tx=0,chunks_rx=0,icmp_replies=0)

@pytest.mark.parametrize('proto',['tcp','http'])
@pytest.mark.parametrize('direction',['ul','dl'])
def test_persistent_framing_reuses_socket_without_mixing_quotas(proto,direction):
    async def run():
        server=await asyncio.start_server(receive_client,'127.0.0.1',0);port=server.sockets[0].getsockname()[1]
        target=dict(host='127.0.0.1',tcp_port=port,http_port=port)
        pool=ConnectionPool(execution_options({},'persistent'))
        try:
            ports=[]
            for size in (1200,601,53):
                e=event(proto,direction,size);m=counters()
                await asyncio.wait_for(traffic(e,target,m,time.monotonic()+1,{'source_ip':'127.0.0.1'},pool),2)
                assert m['bytes_tx' if direction=='ul' else 'bytes_rx']==size
                assert m['receiver_bytes']==size
                ports.append(m['src_port'])
            assert len(set(ports))==1
            assert pool.stats()['opened']==1 and pool.stats()['reused']==2
        finally:await pool.close();server.close();await server.wait_closed()
    asyncio.run(run())


def test_pool_does_not_reuse_partial_transfer():
    async def run():
        server=await asyncio.start_server(receive_client,'127.0.0.1',0);port=server.sockets[0].getsockname()[1]
        pool=ConnectionPool(execution_options({},'persistent'));target=dict(host='127.0.0.1',tcp_port=port,http_port=port)
        try:
            e=event('tcp','ul',12000);m=counters()
            await asyncio.wait_for(traffic(e,target,m,time.monotonic()+.02,{},pool),1)
            assert m['bytes_tx']<e['planned_bytes'] and pool.stats()['idle_connections']==0
            m=counters();await asyncio.wait_for(traffic(event(),target,m,time.monotonic()+1,{},pool),2)
            assert m['bytes_rx']==1200 and pool.stats()['opened']==2
        finally:await pool.close();server.close();await server.wait_closed()
    asyncio.run(run())


def test_background_checkpoint_freezes_state_and_keeps_loop_responsive(tmp_path,monkeypatch):
    async def run():
        m=Manager(tmp_path);m.runs['x']=dict(status='running',elapsed_s=0,duration_s=5)
        m.events['x']={'e':dict(bytes_tx=1)};m.plan_cache['x']={}
        entered=threading.Event();release=threading.Event();written=[]
        def write(snapshot):entered.set();release.wait(2);written.append(snapshot[2]['e']['bytes_tx'])
        monkeypatch.setattr(m,'write_checkpoint',write)
        task=asyncio.create_task(m.persist_async('x'))
        for _ in range(100):
            if entered.is_set():break
            await asyncio.sleep(.01)
        assert entered.is_set()
        m.events['x']['e']['bytes_tx']=99
        ticks=0
        for _ in range(5):await asyncio.sleep(.01);ticks+=1
        assert ticks==5 and not task.done()
        release.set();await task
        assert written==[1]
    asyncio.run(run())


@pytest.mark.skipif(sys.platform=='win32',reason='Linux subprocess pipes and worker signals')
def test_supervisor_two_contexts_one_transport_and_complete_payload(tmp_path):
    async def run():
        server=await asyncio.start_server(receive_client,'127.0.0.1',0);port=server.sockets[0].getsockname()[1]
        cfg=load_lab(ROOT/'config/lab.demo.yaml');cfg['start_lead_s']=.2
        cfg['targets']['victim-web'].update(tcp_port=port,http_port=port)
        for i in (1,2):cfg['nodes']['fixed'+str(i)]=dict(adapter='local',source_ip='127.0.0.'+str(i))
        p=generate(load_profiles(ROOT/'profiles'),7,5);proto=p['events'][0];p['events']=[]
        for source in ('fixed1','fixed2'):
            for repeat in range(2):
                for i,(wire,direction) in enumerate((('tcp','ul'),('tcp','dl'),('http','ul'),('http','dl'))):
                    p['events'].append(dict(proto,event_id=source+'-'+str(repeat)+'-'+str(i),domain='fixed',source=source,protocol=wire,wire_protocol=wire,direction=direction,start_s=.2+repeat*2.5+i*.6,duration_s=.5,rate_bps=19200,rate_fraction=.000192,planned_bytes=1200,packet_size_bytes=200))
        p['summary']=summarize(p);p['plan_hash']=plan_hash(p);path=save_plan(p,tmp_path/'plan.json')
        assert len(resolve(cfg,p))==2 and len(supervisor_groups(resolve(cfg,p)))==1
        manager=Manager(tmp_path/'runs')
        try:
            r=await manager.start(p,path,cfg,mode='lab',speed=1,execution_profile='persistent')
            await asyncio.wait_for(manager.tasks[r['id']],20);result=manager.snapshot(r['id'])
            assert result['status']=='completed',result
            assert result['execution_transport']['sessions']==1 and result['execution_transport']['workers']==2
            assert result['counts']=={'completed':16}
            assert result['bytes_tx']==9600 and result['bytes_rx']==9600
            assert len({e['source_ip'] for e in manager.events[r['id']].values()})==2
            assert sum(a['connections']['reused'] for a in result['agents'].values())>=8
            assert (manager.folder(r['id'])/'benign_plan.json').read_bytes()==path.read_bytes()
        finally:await manager.shutdown();server.close();await server.wait_closed()
    asyncio.run(run())


@pytest.mark.skipif(sys.platform=='win32',reason='Linux child process cleanup')
def test_supervisor_stops_children_on_transport_eof(tmp_path):
    async def run():
        server=await asyncio.start_server(receive_client,'127.0.0.1',0);port=server.sockets[0].getsockname()[1]
        proc=await asyncio.create_subprocess_exec(sys.executable,str(ROOT/'benign_lab/supervisor.py'),'supervisor',stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        session=SupervisorSession(proc,['one','two'])
        e=dict(event(),event_id='e',start_s=20,duration_s=1,destination='victim-web')
        cfg=dict(events=[e],targets={'victim-web':dict(host='127.0.0.1',tcp_port=port,http_port=port)},duration_s=30)
        proc.stdin.write(canonical(dict(workers=[dict(key=k,argv=[sys.executable,str(ROOT/'benign_lab/agent.py'),'worker'],config=cfg) for k in ('one','two')]))+b'\n');await proc.stdin.drain()
        ready=[json.loads(await asyncio.wait_for(c.stdout.readline(),5)) for c in session.channels.values()]
        assert all(r['type']=='ready' for r in ready)
        pids=[r['pid'] for r in ready]
        proc.stdin.close();await asyncio.wait_for(proc.wait(),5)
        await asyncio.gather(session.task,session.error_task)
        for pid in pids:
            with pytest.raises(ProcessLookupError):os.kill(pid,0)
        server.close();await server.wait_closed()
    asyncio.run(run())

def test_checkpoint_cancellation_does_not_release_writer_lock_early(tmp_path,monkeypatch):
    async def run():
        m=Manager(tmp_path);m.runs['x']=dict(status='running',elapsed_s=0,duration_s=5);m.events['x']={'e':dict(bytes_tx=1)};m.plan_cache['x']={}
        entered=threading.Event();release=threading.Event();written=[]
        def write(snapshot):
            if snapshot[2]['e']['bytes_tx']==1:entered.set();release.wait(2)
            written.append(snapshot[2]['e']['bytes_tx'])
        monkeypatch.setattr(m,'write_checkpoint',write)
        first=asyncio.create_task(m.persist_async('x'))
        while not entered.is_set():await asyncio.sleep(.01)
        first.cancel();m.events['x']['e']['bytes_tx']=2
        second=asyncio.create_task(m.persist_async('x'));await asyncio.sleep(.05)
        assert not second.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):await first
        await second;assert written==[1,2]
    asyncio.run(run())


def test_pool_separates_logical_sources_and_bounds_idle_sockets():
    async def run():
        server=await asyncio.start_server(receive_client,'127.0.0.1',0);port=server.sockets[0].getsockname()[1];target=dict(host='127.0.0.1',tcp_port=port,http_port=port)
        options=execution_options({},'persistent');options['max_idle_total']=1;pool=ConnectionPool(options)
        try:
            ports=[]
            for source in ('peer-flow1','peer-flow2'):
                e=dict(event(),source=source);m=counters()
                await traffic(e,target,m,time.monotonic()+1,{},pool);ports.append(m['src_port'])
            assert len(set(ports))==2
            assert pool.stats()['idle_connections']==1 and pool.stats()['open_connections']==1
        finally:await pool.close();server.close();await server.wait_closed()
    asyncio.run(run())


@pytest.mark.skipif(sys.platform=='win32',reason='Linux pipe and process cleanup')
def test_supervisor_reaps_children_when_output_pipe_breaks(tmp_path):
    async def run():
        script=tmp_path/'noisy.py'
        script.write_text("import json,os,time\nprint(json.dumps(dict(type='ready',pid=os.getpid())),flush=True)\ntime.sleep(.3)\nfor i in range(10000):print(json.dumps(dict(type='metrics',message='x'*4096)),flush=True)\ntime.sleep(30)\n")
        proc=await asyncio.create_subprocess_exec(sys.executable,str(ROOT/'benign_lab/supervisor.py'),stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,limit=32*1024*1024)
        proc.stdin.write(canonical(dict(workers=[dict(key='one',argv=[sys.executable,str(script)],config={})]))+b'\n');await proc.stdin.drain()
        ready=json.loads(await asyncio.wait_for(proc.stdout.readline(),5));pid=json.loads(ready['items'][0]['line'])['pid']
        proc.stdout._transport.close()
        await asyncio.wait_for(proc.wait(),7)
        with pytest.raises(ProcessLookupError):os.kill(pid,0)
        proc.stdin.close();await proc.stderr.read()
    asyncio.run(run())


@pytest.mark.parametrize('delay,early',[(0,True),(.11,False)])
def test_persistent_download_preserves_near_deadline_shortfall_rule(delay,early):
    async def run():
        async def partial(reader,writer):
            await reader.readline();writer.write(b'x'*100);await writer.drain();await asyncio.sleep(delay);writer.close();await writer.wait_closed()
        server=await asyncio.start_server(partial,'127.0.0.1',0);port=server.sockets[0].getsockname()[1]
        pool=ConnectionPool(execution_options({},'persistent'));e=event(direction='dl',size=1000);m=counters();target=dict(host='127.0.0.1',tcp_port=port,http_port=port)
        try:
            if early:
                with pytest.raises(ConnectionError):await traffic(e,target,m,time.monotonic()+.2,{},pool)
            else:await traffic(e,target,m,time.monotonic()+.2,{},pool)
            assert m['bytes_rx']==100 and pool.stats()['idle_connections']==0 and pool.stats()['open_connections']==0
        finally:await pool.close();server.close();await server.wait_closed()
    asyncio.run(run())
