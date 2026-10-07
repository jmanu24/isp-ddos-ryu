"""Start the Wi-Fi gateway and safely restore the distributed lab after Windows login."""
import argparse,json,subprocess,time,urllib.request,re,ipaddress
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--config',required=True);a=p.parse_args();path=Path(a.config).resolve();c=json.loads(path.read_text());flags=subprocess.CREATE_NO_WINDOW
def run(args,**kw):return subprocess.run(args,capture_output=True,text=True,creationflags=flags,**kw)
def running():
 r=run([c['vmrun'],'-T','player','list'],check=True);return {str(Path(s).resolve()).lower() for s in r.stdout.splitlines()[1:] if s.strip()}
def start(vmx):
 if str(Path(vmx).resolve()).lower() not in running():run([c['vmrun'],'-T','player','start',vmx,'nogui'],check=True)
ssh=['ssh','-T','-i',c['ssh_key'],'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','ubuntu@192.168.18.154']
r=run(ssh+['python3 /home/ubuntu/isp-ddos-ryu/deploy/vm-lab/tools/workstation/workstation_start_policy.py'],check=True,timeout=40)
policy=json.loads(r.stdout.splitlines()[-1]);assert policy['relay_ip'],'Relay underlay address unavailable'
relay=str(ipaddress.ip_address(policy['relay_ip']));start(c['gateway_vmx'])
for attempt in range(30):
 leases=Path('C:/ProgramData/VMware/vmnetdhcp.leases').read_text()
 matches=[ip for ip,body in re.findall(r'lease ([\d.]+) \{(.*?)\}',leases,re.S) if '00:50:56:3a:a0:00' in body]
 gateway=matches[-1] if matches else c['gateway_underlay']
 command="peer=$(wg show wg0 peers); wg set wg0 peer \"$peer\" endpoint "+relay+":51871; sed -i 's/^Endpoint = .*/Endpoint = "+relay+":51871/' /etc/wireguard/wg0.conf"
 r=run(['ssh','-T','-i',c['ssh_key'],'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','-o','HostKeyAlias=lab-wifi-gateway','-o','UserKnownHostsFile='+c['gateway_known_hosts'],'root@'+gateway,command],timeout=12)
 if r.returncode==0:break
 time.sleep(3)
else:raise RuntimeError('Gateway unavailable')
try:
 req=urllib.request.Request('http://127.0.0.1:18781/states',headers={'Authorization':'Bearer '+c['token']});urllib.request.urlopen(req,timeout=3).close();backend=True
except Exception:backend=False
scripts=Path(__file__).resolve().parent
if not backend:subprocess.Popen([c['python'],str(scripts/'workstation_bridge.py'),'--config',str(path)],creationflags=flags)
if not policy['tunnel_up']:subprocess.Popen([c['python'],str(scripts/'workstation_tunnel.py'),'--config',str(path)],creationflags=flags)
order=['victim','pe']+['ent-site-'+str(i) for i in range(1,6)]+['bng','suscriptor','br','peer-router','peer-router-2']
for n in order:
 if n in policy['permitted'] and Path(c['vms'][n]).exists():start(c['vms'][n])
print('Gateway, administration channel and permitted VMs started')
