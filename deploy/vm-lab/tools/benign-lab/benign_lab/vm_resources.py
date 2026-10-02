"""Guest resources via existing SSH streams and ESXi scheduling counters."""
import asyncio,json,shlex
from .host_monitor import HostMonitor,esxi_sample

def ready_sample(payload,node):
    row=esxi_sample(payload,node['name']);sample=payload['sample'][0]
    values={v.get('instance',''):v['value'][-1] for v in sample['value'] if v['name']=='cpu.ready.summation' and v.get('value') and v['value'][-1]>=0}
    count=node['vcpus'];interval=row['interval_s']
    if interval<=0 or count<=0:raise ValueError('Invalid Ready normalization')
    row.update(platform='esxi_vm',metrics_kind='esxi_vm_cpu',logical_cpus=count,ready_ms=values.get(''),ready_vcpu_pct=100*values['']/(interval*1000*count) if '' in values else None,ready_per_vcpu_pct={k:100*v/(interval*1000) for k,v in values.items() if k},domain=node.get('domain','shared'))
    return row

class VmResourceMonitor(HostMonitor):
    def __init__(self,root,cfg):
        guests=cfg.get('traffic_monitor',{}).get('nodes',[]);self.ready=cfg.get('vm_resource_monitor',{}).get('esxi_vms',[])
        hosts=[dict(name=n['name']) for n in guests]+[dict(name='ESXi/'+n['name']) for n in self.ready]
        super().__init__(root,{'host_monitor':{'hosts':hosts,'retention_s':cfg.get('vm_resource_monitor',{}).get('retention_s',21600)}})
    def accept(self,node,row):super().accept(node,dict(row,domain=node.get('domain','shared')))
    async def batch(self,env,object_path):
        cmd='set -a; . '+shlex.quote(env)+'; set +a; govc metric.sample -json -n 1 '+shlex.quote(object_path)+' cpu.usage.average cpu.ready.summation'
        p=await asyncio.create_subprocess_exec('bash','-c',cmd,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        try:out,_=await asyncio.wait_for(p.communicate(),12)
        except BaseException:
            if p.returncode is None:p.kill();await p.wait()
            raise
        if p.returncode:raise RuntimeError('VM metrics unavailable')
        return {str(s['entity']['value']):s for s in json.loads(out).get('sample',[])}
    async def collect_batch(self,env,path,nodes):
        while True:
            begin=asyncio.get_running_loop().time()
            try:samples=await self.batch(env,path)
            except asyncio.CancelledError:raise
            except Exception:samples={}
            for n in nodes:
                node=dict(n,name='ESXi/'+n['name'])
                try:self.accept(node,ready_sample({'sample':[samples[str(n['entity'])]]},n))
                except Exception:self.nodes[node['name']]=dict(self.nodes[node['name']],status='disconnected',error='CPU Ready no disponible')
            await asyncio.sleep(max(1,20-(asyncio.get_running_loop().time()-begin)))
    def start(self):
        groups={}
        for n in self.ready:groups.setdefault((n['govc_env'],n['object'].rsplit('/',1)[0]+'/*'),[]).append(n)
        self.tasks=[asyncio.create_task(self.collect_batch(env,path,nodes)) for (env,path),nodes in groups.items()]
