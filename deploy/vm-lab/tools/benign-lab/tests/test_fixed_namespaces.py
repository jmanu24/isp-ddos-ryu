import asyncio,json
from benign_lab.baseline import BaselineGuard
from benign_lab.config import command,executor_for

def test_fixed_namespace_execution_requires_isolation():
 cfg=dict(require_explicit_mapping=True,nodes={'fixed3':dict(configured=True,adapter='ssh_netns',host='10.10.0.9',user='labadmin',sudo=True,namespace='fixed3',source_ip='10.20.0.3',interface='macvlan3',session_id='ipoe2',access_mode='ipoe_namespace')})
 assert 'sudo -n ip netns exec fixed3' in command(executor_for(cfg,dict(domain='fixed',source='fixed3')))[-1]

def test_baseline_reads_each_namespace_instead_of_host():
 cfg=dict(baseline_control=dict(fixed_host='10.10.0.9',fixed_user='labadmin'),nodes={f'fixed{i}':dict(namespace=f'fixed{i}',access_mode='ipoe_namespace') for i in range(1,11)})
 guard=BaselineGuard(cfg,'test',5);calls=[]
 async def ssh(*args,**kwargs):
  calls.append(kwargs['payload']);return '[]'
 guard.ssh=ssh
 assert asyncio.run(guard.fixed_addresses())==[]
 assert "'fixed10'" in calls[0] and "'fixed1'" in calls[0]
 assert "argv=['ip','netns','exec',ns]+argv" in calls[0]
