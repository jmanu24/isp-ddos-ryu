"""Baseline control through the control node; no credentials in commands."""
from pathlib import Path
import hashlib
import re
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
        self.domains={'mobile','fixed','enterprise','peering'}

    async def ssh(self,host,user,command,root=False,payload=None,timeout=25):
        env=os.environ.copy()
        password=env.get(self.control.get('pe_password_env','BENIGN_PE_SSH_PASSWORD') if user=='root' else self.control.get('password_env','BENIGN_SSH_PASSWORD'))
        if not password: raise RuntimeError('Baseline SSH credential is unavailable')
        env['SSHPASS']=password
        argv=['sshpass','-e','ssh','-T','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','-o','UserKnownHostsFile='+self.control['known_hosts_file'],user+'@'+host,('sudo -n ' if root and user!='root' else '')+command]
        proc=await asyncio.create_subprocess_exec(*argv,stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env=env)
        try:
            out,err=await asyncio.wait_for(proc.communicate(payload.encode() if payload else None),timeout)
        except asyncio.TimeoutError as exc:
            proc.kill();await proc.wait()
            raise RuntimeError('Remote operation timed out after '+str(timeout)+'s on '+host) from exc
        except BaseException:
            proc.kill();await proc.wait();raise
        if proc.returncode:raise RuntimeError('Baseline remote operation failed on '+host+': '+err.decode(errors='replace')[-500:])
        return out.decode()

    async def controller(self,code,timeout=25):
        return await self.ssh(self.control['host'],self.control['user'],'python3 -',root=True,payload=code,timeout=timeout)

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

    async def prepare_fixed(self,reconnect=False):
        """Refresh runtime mappings without changing the detection pipeline.

        Reconnect missing leases only when baseline explicitly permits it.
        """
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
        if reconnect:
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
            expected=sum(n.get('access_mode') in ('ipoe_bound','ipoe_namespace') for n in self.cfg['nodes'].values())
            valid=len(mapping)==expected and len(set(mapping.values()))==expected and set(mapping.values()).issubset(set(active_ips))
            if valid and mapping==stable:break
            stable=mapping if valid else None
            await asyncio.sleep(2)
        else:raise RuntimeError('Fixed preparation requires stable namespace IPs matching active BNG sessions')
        session_ids={line.split('|')[3].strip():line.split('|')[0].strip() for line in sessions.splitlines() if len(line.split('|'))>=7 and 'active' in line}
        for name,address in mapping.items():
            self.cfg['nodes'][name]['source_ip']=address
            self.cfg['nodes'][name]['session_id']=session_ids[address]
        return dict(sessions=sessions,mapping={name:dict(source_ip=self.cfg['nodes'][name]['source_ip'],session_id=self.cfg['nodes'][name]['session_id'],namespace=self.cfg['nodes'][name].get('namespace',''),interface=self.cfg['nodes'][name]['interface']) for name in mapping})

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
        mobile=None
        if 'mobile' in self.domains:
            expected={name:n['source_ip'] for name,n in self.cfg['nodes'].items()
                      if re.fullmatch(r'ue[1-5]',name) and n.get('configured',True)}
            source=Path(__file__).with_name('mobile_budget.py').read_text(encoding='utf-8')
            params=dict(core_url=self.control.get('mobile_telemetry_url','http://10.10.0.5:8766/telemetry'),
                        ric_url=self.control['ric_url'],expected_ips=expected,run_id=self.run_id)
            code=source+'\nparams='+repr(params)+'\nresult=restore_mobile_budgets(**params)\nprint(json.dumps(result))\n'
            mobile=json.loads(await self.controller(code,timeout=75))
            mobile['preflight_source_sha256']=hashlib.sha256(source.encode()).hexdigest()
        # Verify dataplane restrictions without deleting unidentified rules.
        flows=await self.ssh(self.control['pe_host'],'root','ovs-ofctl -O OpenFlow13 dump-flows br-ent')
        residual=[line for line in flows.splitlines() if 'priority=100' in line and 'actions=drop' in line]
        if residual:raise RuntimeError('Residual OpenFlow drop rules; baseline cannot start until identified restrictions are released')
        sessions=None
        if 'fixed' in self.domains:
            sessions=(await self.prepare_fixed(reconnect=True))['sessions']
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
