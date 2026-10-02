"""Install read-only interface probes using the repository VM inventory."""
import base64,concurrent.futures,json,os,shlex,subprocess,sys
from pathlib import Path
import yaml
root=Path('/home/ubuntu/isp-ddos-ryu');app=root/'deploy/vm-lab/tools/benign-lab'
sys.path.insert(0,str(root/'deploy/vm-lab'))
from webtool.inventory import NODES,UE_NETNS,credentials_for
payload=base64.b64encode((app/'benign_lab/interface_probe.py').read_bytes()).decode()
def install(n):
 user,password=credentials_for(n.name);host=n.ip or '10.30.0.2';env=os.environ.copy();env['SSHPASS']=password
 code="from pathlib import Path;import base64; p=Path('/opt/benign-lab/interface_probe.py');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(base64.b64decode('"+payload+"'));p.chmod(0o755)"
 command=('sudo -n ' if user!='root' else '')+'python3 -c '+shlex.quote(code)
 result=subprocess.run(['sshpass','-e','ssh','-T','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5',user+'@'+host,command],env=env,capture_output=True,text=True,timeout=30)
 if result.returncode:raise RuntimeError(n.name+': '+result.stderr[-300:])
 preferred={'core5g':'ens192','pe':'br-ent','victim':'eth1','peer-router':'ens160'}.get(n.name,'ens160' if n.domain=='enterprise' else 'ens192')
 return dict(name=n.name,domain={'broadband':'fixed','bgp':'peering'}.get(n.domain,n.domain),host=host,user=user,password_env='BENIGN_PE_SSH_PASSWORD' if user=='root' else 'BENIGN_SSH_PASSWORD',known_hosts_file='/home/ubuntu/.ssh/known_hosts',python='python3',sudo=user!='root',namespaces=[u.netns for u in UE_NETNS if u.host==n.name],fixed=n.name=='suscriptor',preferred_interface=preferred)
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:nodes=list(pool.map(install,NODES))
nodes.append(dict(name='control',domain='control',adapter='local',preferred_interface='ens160'))
p=app/'config/lab.connected.yaml';cfg=yaml.safe_load(p.read_text());cfg['traffic_monitor']=dict(interval_s=5,retention_s=21600,nodes=nodes);p.write_text(yaml.safe_dump(cfg,sort_keys=False))
print(json.dumps(dict(installed=len(NODES),collectors=len(nodes))))
