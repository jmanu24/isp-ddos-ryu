"""Persistent SSH collectors and a bounded SQLite history of real counters."""
import asyncio
import json
import os
import shlex
import sqlite3
import sys
import time
from pathlib import Path


class InterfaceMonitor:
    def __init__(self,root,cfg):
        self.cfg=cfg.get('traffic_monitor',{})
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(str(self.root/'interface_metrics.sqlite'),check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS samples (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, element TEXT, domain TEXT, body TEXT)')
        self.db.execute('CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts)')
        self.db.commit()
        self.tasks=[];self.processes=set();self.nodes={n['name']:dict(name=n['name'],domain=n['domain'],status='connecting') for n in self.cfg.get('nodes',[])};self.last_prune=0
        self.running=False

    def accept(self,node,message):
        received=time.time();rows=[]
        for raw in message['items']:
            namespace=raw.get('namespace','')
            element=namespace or (('fixed'+raw['interface'][7:]) if node.get('fixed') and raw['interface'].startswith('macvlan') else (node['name']+' (VM)' if node.get('namespaces') else node['name']))
            row=dict(raw,node=node['name'],element=element,domain=node['domain'],timestamp=message['timestamp'],received_at=received,preferred_interface=node.get('preferred_interface',''),metrics_kind='linux_interface_counters')
            self.db.execute('INSERT INTO samples(ts,element,domain,body) VALUES(?,?,?,?)',(row['timestamp'],element,node['domain'],json.dumps(row)))
            rows.append(row)
        self.db.commit()
        self.nodes[node['name']]=dict(name=node['name'],domain=node['domain'],status='connected',received_at=received,namespace_errors=message.get('errors',{}),interfaces=len(rows))
        if received-self.last_prune>300:
            self.db.execute('DELETE FROM samples WHERE ts<?',(received-self.cfg.get('retention_s',21600),));self.db.commit();self.last_prune=received

    def rows(self,start,end,after=0,element='',domain='',limit=100000):
        where=['ts>=?','ts<=?','id>?'];args=[start,end,after]
        if element:where.append('element=?');args.append(element)
        if domain:where.append('domain=?');args.append(domain)
        records=self.db.execute('SELECT id,body FROM samples WHERE '+' AND '.join(where)+' ORDER BY id LIMIT ?',args+[limit]).fetchall()
        return [dict(json.loads(body),id=key) for key,body in records]

    def response(self,minutes=5,after=0):
        now=time.time()
        rows=self.rows(now-minutes*60,now,after)
        return dict(metrics_kind='linux_interface_counters',timestamp=now,enabled=bool(self.cfg.get('nodes')),interval_s=self.cfg.get('interval_s',5),nodes=list(self.nodes.values()),items=rows,cursor=max((r['id'] for r in rows),default=after),retention_s=self.cfg.get('retention_s',21600))

    def argv(self,node):
        path=node.get('probe_path','/opt/benign-lab/interface_probe.py')
        args=[node.get('python','python3'),'-u',path,'--interval',str(self.cfg.get('interval_s',5)),'--namespaces',','.join(node.get('namespaces',[]))]
        if node.get('adapter')=='local':return [sys.executable,'-u',str(Path(__file__).with_name('interface_probe.py'))]+args[3:]
        command=('sudo -n ' if node.get('sudo') else '')+' '.join(shlex.quote(a) for a in args)
        ssh=['ssh','-T','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2','-o','UserKnownHostsFile='+node['known_hosts_file']]
        if node.get('identity_file'):
            ssh+=['-i',node['identity_file'],'-o','BatchMode=yes']
        else:
            ssh=['sshpass','-e']+ssh
        return ssh+[node['user']+'@'+node['host'],command]

    async def collect(self,node):
        delay=5
        while True:
            proc=None;stderr_task=None
            try:
                env=os.environ.copy()
                if node.get('adapter')!='local' and not node.get('identity_file'):
                    secret=env.get(node.get('password_env','BENIGN_SSH_PASSWORD'))
                    if not secret:raise RuntimeError('SSH credential unavailable')
                    env['SSHPASS']=secret
                proc=await asyncio.create_subprocess_exec(*self.argv(node),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env=env,limit=1024*1024)
                self.processes.add(proc)
                async def drain():
                    while await proc.stderr.read(4096):pass
                stderr_task=asyncio.create_task(drain())
                while True:
                    line=await asyncio.wait_for(proc.stdout.readline(),max(20,self.cfg.get('interval_s',5)*4))
                    if not line:raise RuntimeError('Collector disconnected')
                    self.accept(node,json.loads(line));delay=5
            except asyncio.CancelledError:raise
            except Exception as exc:
                old=self.nodes.get(node['name'],{})
                self.nodes[node['name']]=dict(old,name=node['name'],domain=node['domain'],status='disconnected',error=str(exc))
            finally:
                if stderr_task:
                    stderr_task.cancel();await asyncio.gather(stderr_task,return_exceptions=True)
                if proc:
                    if proc.returncode is None:
                        proc.terminate()
                        try:await asyncio.wait_for(proc.wait(),2)
                        except asyncio.TimeoutError:proc.kill();await proc.wait()
                    self.processes.discard(proc)
            await asyncio.sleep(delay);delay=min(30,delay*2)

    def start(self):
        self.running=True
        self.tasks=[asyncio.create_task(self.collect(n)) for n in self.cfg.get('nodes',[])]

    async def stop(self):
        for task in self.tasks:task.cancel()
        await asyncio.gather(*self.tasks,return_exceptions=True)
        self.db.close();self.running=False
