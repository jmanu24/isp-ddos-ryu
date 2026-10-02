import asyncio,json,sqlite3,time,shlex,urllib.request
from datetime import datetime
from pathlib import Path

def esxi_sample(payload,host):
    sample=payload['sample'][0]; info=sample['sampleInfo'][-1]
    metrics={v['name']:v['value'][-1] for v in sample['value'] if not v.get('instance') and v.get('value') and v['value'][-1]>=0}
    if 'cpu.usage.average' not in metrics: raise ValueError('CPU aggregate unavailable')
    cores={v['instance']:v['value'][-1]/100 for v in sample['value'] if v['name']=='cpu.usage.average' and v.get('instance') and v.get('value') and v['value'][-1]>=0}
    return dict(host=host,platform='esxi',timestamp=datetime.fromisoformat(info['timestamp'].replace('Z','+00:00')).timestamp(),interval_s=info['interval'],cpu_pct=metrics['cpu.usage.average']/100,cpu_mhz=metrics.get('cpu.usagemhz.average'),logical_cpus=len(cores),per_cpu_pct=cores,metrics_kind='host_cpu')

class HostMonitor:
    def __init__(self,root,cfg):
        self.cfg=cfg.get('host_monitor',{});self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(str(self.root/'host_metrics.sqlite'),check_same_thread=False);self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS samples(id INTEGER PRIMARY KEY,ts REAL,host TEXT,body TEXT,UNIQUE(host,ts))');self.db.execute('CREATE INDEX IF NOT EXISTS host_ts ON samples(ts)');self.db.commit()
        self.tasks=[];self.nodes={n['name']:dict(name=n['name'],status='connecting') for n in self.cfg.get('hosts',[])}
    def accept(self,node,row):
        if not 0<=float(row['cpu_pct'])<=100:raise ValueError('Invalid CPU percentage')
        now=time.time();row=dict(row,host=node['name'],received_at=now,metrics_kind='host_cpu')
        self.db.execute('INSERT OR IGNORE INTO samples(ts,host,body) VALUES(?,?,?)',(row['timestamp'],node['name'],json.dumps(row)))
        self.db.execute('DELETE FROM samples WHERE ts<?',(now-self.cfg.get('retention_s',21600),));self.db.commit()
        self.nodes[node['name']]=dict(name=node['name'],status='connected',received_at=now,timestamp=row['timestamp'],interval_s=row['interval_s'])
    def rows(self,start,end,after=0):
        return [dict(json.loads(body),id=i) for i,body in self.db.execute('SELECT id,body FROM samples WHERE ts>=? AND ts<=? AND id>? ORDER BY id LIMIT 100000',(start,end,after))]
    def response(self,minutes=5,after=0):
        now=time.time();rows=self.rows(now-minutes*60,now,after)
        return dict(items=rows,cursor=max((r['id'] for r in rows),default=after),hosts=list(self.nodes.values()),enabled=bool(self.nodes),retention_s=self.cfg.get('retention_s',21600))
    async def sample(self,n):
        if n['adapter']=='workstation':
            def fetch():
                c=json.loads(Path(n['config_file']).read_text()); req=urllib.request.Request(c['url']+'/resources',headers={'Authorization':'Bearer '+c['token']})
                with urllib.request.urlopen(req,timeout=8) as r:return json.load(r)
            return await asyncio.get_running_loop().run_in_executor(None,fetch)
        cmd='set -a; . '+shlex.quote(n['govc_env'])+'; set +a; govc metric.sample -json -n 1 '+shlex.quote(n['object'])+' cpu.usage.average cpu.usagemhz.average'
        p=await asyncio.create_subprocess_exec('bash','-c',cmd,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        try:out,err=await asyncio.wait_for(p.communicate(),12)
        except BaseException:
            if p.returncode is None:p.kill();await p.wait()
            raise
        if p.returncode:raise RuntimeError('ESXi collector unavailable')
        return esxi_sample(json.loads(out),n['name'])
    async def collect(self,n):
        while True:
            try:self.accept(n,await self.sample(n))
            except asyncio.CancelledError:raise
            except Exception:self.nodes[n['name']]=dict(self.nodes[n['name']],status='disconnected',error='No se pudo obtener CPU del host')
            await asyncio.sleep(n.get('poll_s',5 if n['adapter']=='workstation' else 20))
    def start(self):self.tasks=[asyncio.create_task(self.collect(n)) for n in self.cfg.get('hosts',[])]
    async def stop(self):
        for t in self.tasks:t.cancel()
        await asyncio.gather(*self.tasks,return_exceptions=True);self.db.close()
