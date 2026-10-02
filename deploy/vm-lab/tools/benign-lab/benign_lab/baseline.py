"""Baseline control through the control node; no credentials in commands."""
import asyncio
import json
import os
import shlex
import time
from .planner import canonical


class BaselineGuard:
    def __init__(self,cfg,run_id,duration):
        self.cfg=cfg
        self.control=cfg['baseline_control']
        self.run_id=run_id
        self.duration=duration
        self.acquired=False

    async def ssh(self,host,user,command,root=False,payload=None):
        env=os.environ.copy()
        password=env.get(self.control.get('pe_password_env','BENIGN_PE_SSH_PASSWORD') if user=='root' else self.control.get('password_env','BENIGN_SSH_PASSWORD'))
        if not password: raise RuntimeError('Baseline SSH credential is unavailable')
        env['SSHPASS']=password
        argv=['sshpass','-e','ssh','-T','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','-o','UserKnownHostsFile='+self.control['known_hosts_file'],user+'@'+host,('sudo -n ' if root and user!='root' else '')+command]
        proc=await asyncio.create_subprocess_exec(*argv,stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env=env)
        try:
            out,err=await asyncio.wait_for(proc.communicate(payload.encode() if payload else None),25)
        except BaseException:
            proc.kill();await proc.wait();raise
        if proc.returncode:raise RuntimeError('Baseline remote operation failed on '+host+': '+err.decode(errors='replace')[-500:])
        return out.decode()

    async def controller(self,code):
        return await self.ssh(self.control['host'],self.control['user'],'python3 -',root=True,payload=code)

    async def status(self):
        return json.loads(await self.controller("from pathlib import Path; print(Path('/run/benign-baseline/status.json').read_text())"))

    async def fixed_addresses(self):
        namespaces=sorted({n.get('namespace','') for n in self.cfg['nodes'].values() if n.get('access_mode') in ('ipoe_bound','ipoe_namespace')})
        code="""import json,subprocess
result=[]
for ns in NAMESPACES:
 argv=['ip','-j','-4','address']
 if ns:argv=['ip','netns','exec',ns]+argv
 rows=json.loads(subprocess.check_output(argv))
 for row in rows:row['namespace']=ns
 result.extend(rows)
print(json.dumps(result))
""".replace('NAMESPACES',repr(namespaces))
        return json.loads(await self.ssh(self.control['fixed_host'],self.control['fixed_user'],'python3 -',root=True,payload=code))

    async def enter(self):
        flags=await self.ssh(self.control['host'],self.control['user'],'systemctl show ryu-manager -p Environment')
        if 'LAB_CALIBRATION_MODE=true' in flags:raise RuntimeError('An external calibration session is active')
        # A finite lease restores the pipeline even after dashboard/process failure.
        code="""import json,time
from pathlib import Path
p=Path('/run/benign-baseline/lease.json');p.parent.mkdir(exist_ok=True)
import fcntl
lock=(p.parent/'lease.lock').open('w');fcntl.flock(lock,fcntl.LOCK_EX)
if p.exists():
 old=json.loads(p.read_text())
 if old['expires_at']>time.time():raise RuntimeError('Another baseline lease is active')
v=dict(run_id=RUN_ID,expires_at=time.time()+TTL)
t=p.with_suffix('.tmp');t.write_text(json.dumps(v));t.replace(p)
print(json.dumps(v))
""".replace('RUN_ID',repr(self.run_id)).replace('TTL',str(self.duration+240))
        lease=json.loads(await self.controller(code))
        self.acquired=True
        for _ in range(90):
            try:state=await self.status()
            except (RuntimeError,ValueError):state={}
            if state.get('run_id')==self.run_id and state.get('active'):
                if state.get('error'):raise RuntimeError('Baseline could not clear previous mitigations: '+str(state['error']))
                if state.get('cleared'):break
            await asyncio.sleep(1)
        else:raise RuntimeError('Controller did not acknowledge baseline mode')
        # Restore all UE slice budgets, including actuator state left after a restart.
        code="""import json,time,urllib.request
url=RIC_URL
s=json.load(urllib.request.urlopen(url+'/status',timeout=5))
for imsi in s['enforced']:
 req=urllib.request.Request(url+'/rc',data=json.dumps(dict(imsi=imsi,action='unblock',attack_type='BENIGN_BASELINE')).encode(),headers={'Content-Type':'application/json'})
 urllib.request.urlopen(req,timeout=5).read()
for _ in range(20):
 s=json.load(urllib.request.urlopen(url+'/status',timeout=5))
 if len(s['enforced'])==5 and all(x.get('action')=='unblock' and x.get('max_prb')==100 for x in s['enforced'].values()):break
 time.sleep(.5)
else:raise RuntimeError('UE slice budgets were not restored')
print(json.dumps(s))
"""
        code=code.replace('RIC_URL',repr(self.control['ric_url']))
        mobile=json.loads(await self.controller(code))
        # Verify dataplane restrictions without deleting unidentified rules.
        flows=await self.ssh(self.control['pe_host'],'root','ovs-ofctl -O OpenFlow13 dump-flows br-ent')
        residual=[line for line in flows.splitlines() if 'priority=100' in line and 'actions=drop' in line]
        if residual:raise RuntimeError('Residual OpenFlow drop rules; baseline cannot start until identified restrictions are released')
        # Reconnect only leases missing from BNG; healthy sessions retain their IP.
        import re
        sessions=await self.ssh(self.control['bng_host'],self.control['bng_user'],'accel-cmd -p 2000 show sessions',root=True)
        active_ips=re.findall(r'\|\s*(10\.20\.0\.\d+)\s*\|\s*ipoe\s*\|.*?active',sessions)
        refresh=r"""import json,subprocess
healthy=HEALTHY
addresses=ADDRESSES
missing=[a['local'] for i in addresses if i['ifname'].startswith('macvlan') for a in i['addr_info'] if a['family']=='inet' and a['local'] not in healthy]
if missing:
 with open('/run/bng-agent/cmd','w') as fifo:
  for address in missing:fifo.write('kick '+address+'\n');fifo.flush()
""".replace('HEALTHY',repr(active_ips)).replace('ADDRESSES',repr(await self.fixed_addresses()))
        await self.ssh(self.control['fixed_host'],self.control['fixed_user'],'python3 -',root=True,payload=refresh)
        stable=None
        for _ in range(40):
            sessions=await self.ssh(self.control['bng_host'],self.control['bng_user'],'accel-cmd -p 2000 show sessions',root=True)
            active_ips=re.findall(r'\|\s*(10\.20\.0\.\d+)\s*\|\s*ipoe\s*\|.*?active',sessions)
            addresses=await self.fixed_addresses()
            mapping={}
            for name,node in self.cfg['nodes'].items():
                if node.get('access_mode') in ('ipoe_bound','ipoe_namespace'):
                    matches=[a['local'] for i in addresses if i['ifname']==node['interface'] and i.get('namespace','')==node.get('namespace','') for a in i['addr_info'] if a['family']=='inet']
                    if len(matches)==1:mapping[name]=matches[0]
            valid=len(mapping)==10 and len(active_ips)==10 and set(mapping.values())==set(active_ips)
            if valid and mapping==stable:break
            stable=mapping if valid else None
            await asyncio.sleep(2)
        else:raise RuntimeError('Baseline requires ten stable Fixed IPs matching active BNG sessions')
        session_ids={line.split('|')[3].strip():line.split('|')[0].strip() for line in sessions.splitlines() if len(line.split('|'))>=7 and 'active' in line}
        for name,address in mapping.items():
            self.cfg['nodes'][name]['source_ip']=address
            self.cfg['nodes'][name]['session_id']=session_ids[address]
        state=await self.status()
        if not state.get('active') or state.get('run_id')!=self.run_id:raise RuntimeError('Baseline lease expired during preparation')
        return dict(lease=lease,controller=state,mobile=mobile,openflow_residual_drops=0,fixed_sessions=sessions)

    async def monitor(self):
        while True:
            await asyncio.sleep(5)
            state=await self.status()
            if not state.get('active') or not state.get('cleared') or state.get('run_id')!=self.run_id or time.time()-state.get('heartbeat',0)>30:
                raise RuntimeError('Baseline suspension lost; stopping traffic')

    async def leave(self):
        if not self.acquired:return dict(restored=True,changed=False)
        await self.controller("import json; from pathlib import Path; p=Path('/run/benign-baseline/lease.json'); v=json.loads(p.read_text()) if p.exists() else {}; p.unlink() if v.get('run_id')=="+repr(self.run_id)+" else None")
        for _ in range(30):
            state=await self.status()
            if not state.get('active'):
                return dict(restored=True,controller=state)
            await asyncio.sleep(1)
        raise RuntimeError('Pipeline restoration was not acknowledged')
