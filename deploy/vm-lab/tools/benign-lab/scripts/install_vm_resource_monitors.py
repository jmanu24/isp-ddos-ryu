import sys,json,subprocess,os,shlex,concurrent.futures
from pathlib import Path
root=Path('/home/ubuntu/isp-ddos-ryu');app=root/'deploy/vm-lab/tools/benign-lab';sys.path.insert(0,str(root/'deploy/vm-lab'));sys.path.insert(0,str(app))
from benign_lab.config import load_lab
from benign_lab.runner import TERMINAL
from webtool.govc_ops import _govc
active=[json.loads(p.read_text())['id'] for p in (root/'.runtime/benign-lab/data/runs').glob('*/run.json') if json.loads(p.read_text())['status'] not in TERMINAL]
if active:raise RuntimeError('Experiment active; no restart: '+str(active))
import yaml
path=app/'config/lab.connected.yaml';cfg=load_lab(path);info=json.loads(_govc(['vm.info','-json','*']).stdout);domains={n['name']:n['domain'] for n in cfg['traffic_monitor']['nodes']};workstation=json.loads((root/'.runtime/benign-lab/workstation.json').read_text())['vms'];ready=[]
for vm in info.get('virtualMachines',[]):
 name=vm.get('name') or vm['config']['name'];power=vm.get('runtime',{}).get('powerState') or vm.get('summary',{}).get('runtime',{}).get('powerState')
 if power=='poweredOn' and name not in workstation:
  ready.append(dict(name=name,domain=domains.get(name,'shared'),vcpus=vm['config']['hardware']['numCPU'],object='/ha-datacenter/vm/'+name,entity=vm['self']['value'],govc_env=str(root/'deploy/vm-lab/.govc.env')))
raw=yaml.safe_load(path.read_text());raw['vm_resource_monitor']={'retention_s':21600,'esxi_vms':ready};path.write_text(yaml.safe_dump(raw,sort_keys=False,allow_unicode=True))
env=os.environ.copy()
for l in (root/'.runtime/benign-lab/web.env').read_text().splitlines():
 if '=' in l and not l.startswith('#'):
  k,v=l.split('=',1);env[k]=shlex.split(v)[0] if v else ''
def deploy(n):
 if n.get('adapter')=='local':return n['name']+' local'
 args=['-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','-o','UserKnownHostsFile='+n['known_hosts_file']];e=env.copy();prefix=[]
 if n.get('identity_file'):args+=['-i',n['identity_file'],'-o','BatchMode=yes']
 else:e['SSHPASS']=env[n.get('password_env','BENIGN_SSH_PASSWORD')];prefix=['sshpass','-e']
 target=n['user']+'@'+n['host'];directory='/opt/benign-lab';staging='/tmp/ddos-pucp-resource-probes'
 run=lambda cmd:subprocess.run(cmd,env=e,capture_output=True,text=True,timeout=30,check=True)
 run(prefix+['ssh',*args,target,'mkdir -p '+staging])
 for name in ['interface_probe.py','resource_probe.py']:run(prefix+['scp',*args,str(app/'benign_lab'/name),target+':'+staging+'/'+name])
 command=('sudo -n ' if n.get('sudo') else '')+'cp '+staging+'/interface_probe.py '+staging+'/resource_probe.py '+directory+'/'
 run(prefix+['ssh',*args,target,command]);return n['name']+' installed'
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
 for result in pool.map(deploy,cfg['traffic_monitor']['nodes']):print(result,flush=True)
print('ESXi Ready VMs',len(ready),flush=True)
