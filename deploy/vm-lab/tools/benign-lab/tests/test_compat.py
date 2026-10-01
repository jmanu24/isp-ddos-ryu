import asyncio
from asyncio import TimeoutError
import pytest
from benign_lab.agent import AsyncTimeout
from benign_lab.config import command


def test_deadline_and_external_cancellation():
    async def scenario():
        with pytest.raises(TimeoutError):
            async with AsyncTimeout(.01): await asyncio.sleep(1)
        async def waiting():
            async with AsyncTimeout(10): await asyncio.sleep(20)
        task=asyncio.create_task(waiting())
        await asyncio.sleep(.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(scenario())


def test_control_node_bridge_contains_no_password():
    argv=command(dict(adapter='ssh_netns',host='10.10.0.8',user='labadmin',namespace='ue1',sudo=True,control_node='ubuntu@192.168.18.154',control_identity_file='/tmp/key'))
    assert 'ubuntu@192.168.18.154' in argv
    assert 'ssh_bridge.py' in argv[-1] and 'ip netns exec ue1' in argv[-1]
    assert '--credentials' in argv[-1]


def test_snapshot_exposes_payload_shortfall(tmp_path):
    from benign_lab.runner import Manager
    m=Manager(tmp_path)
    m.runs['pilot']=dict(status='completed_with_errors',duration_s=5,elapsed_s=5)
    m.events['pilot']={'x':dict(domain='fixed',status='completed',bytes_tx=1000,bytes_rx=0,shortfall_bytes=200,rate_bps=3200,error='shortfall')}
    m.logs['pilot']=[]
    assert m.snapshot('pilot')['shortfall_bytes']==200
