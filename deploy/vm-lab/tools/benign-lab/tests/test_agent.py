import asyncio
import json
import socket
import sys
import time
import pytest
from benign_lab import agent
from benign_lab.config import ROOT,command


def test_adapter_quoting():
    cmd=command(dict(adapter='ssh_netns',host='10.0.0.1',user='lab',namespace='ue1',sudo=True,agent_path='/opt/lab space/agent.py'))
    assert cmd[:2]==['ssh','-T']
    assert cmd[-1]=="sudo -n ip netns exec ue1 python3 '/opt/lab space/agent.py' worker"


@pytest.mark.skipif(sys.platform=='win32', reason='Worker uses Linux stdin pipes and POSIX signals; validate on lab host')
def test_real_tcp_udp_http_bidirectional_and_worker_cancellation():
    async def scenario():
        tcp=await asyncio.start_server(agent.receive_client,'127.0.0.1',0)
        port=tcp.sockets[0].getsockname()[1]
        udp,_=await asyncio.get_running_loop().create_datagram_endpoint(agent.UDPReceiver,local_addr=('127.0.0.1',0))
        uport=udp.get_extra_info('sockname')[1]
        target=dict(host='127.0.0.1',tcp_port=port,http_port=port,udp_port=uport)
        try:
            for proto in ('tcp','http','udp'):
                for direction in ('ul','dl'):
                    e=dict(planned_bytes=1200,rate_bps=96000,packet_size_bytes=200,wire_protocol=proto,direction=direction)
                    metrics=dict(bytes_tx=0,bytes_rx=0,chunks_tx=0,chunks_rx=0,icmp_replies=0)
                    await asyncio.wait_for(agent.traffic(e,target,metrics,time.monotonic()+1),2)
                    assert metrics['bytes_tx' if direction=='ul' else 'bytes_rx']==1200,(proto,direction,metrics)
            proc=await asyncio.create_subprocess_exec(sys.executable,str(ROOT/'benign_lab/agent.py'),'worker',stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            event=dict(event_id='test',start_s=20,duration_s=1,planned_bytes=1200,rate_bps=9600,packet_size_bytes=200,wire_protocol='tcp',direction='ul',destination='victim-web')
            proc.stdin.write((json.dumps(dict(events=[event],targets={'victim-web':target},duration_s=30))+'\n').encode())
            await proc.stdin.drain()
            ready=json.loads(await asyncio.wait_for(proc.stdout.readline(),5))
            assert ready['type']=='ready',ready
            proc.stdin.write((json.dumps(dict(start_unix=time.time()+.1))+'\nSTOP\n').encode())
            await proc.stdin.drain()
            output=await asyncio.wait_for(proc.stdout.read(),3)
            await proc.wait()
            assert b'cancelled' in output and b'done' in output and proc.returncode==0,output
        finally:
            tcp.close()
            await tcp.wait_closed()
            udp.close()
    asyncio.run(scenario())
