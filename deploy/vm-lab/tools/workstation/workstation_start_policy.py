"""Read-only startup policy: permit only owned VMs whose retained ESXi originals are off."""
import json,subprocess,socket,ipaddress
from pathlib import Path
r=Path('/home/ubuntu/isp-ddos-ryu');c=json.loads((r/'.runtime/benign-lab/workstation.json').read_text())
e=subprocess.run(['bash','-c','set -a; source /home/ubuntu/isp-ddos-ryu/deploy/vm-lab/.govc.env; env -0'],capture_output=True,check=True)
env=dict(x.decode().split('=',1) for x in e.stdout.split(b'\0') if b'=' in x)
rows=json.loads(subprocess.check_output(['govc','vm.info','-json','*'],env=env))['virtualMachines'];byname={v['name']:v for v in rows}
permitted=[n for n in c['vms'] if byname.get(n,{}).get('runtime',{}).get('powerState')=='poweredOff']
relay=byname['lab-wifi-relay'];ips=[ip for nic in relay.get('guest',{}).get('net',[]) if nic.get('network')==c.get('relay_network','VM Network') for ip in nic.get('ipAddress',[]) if ipaddress.ip_address(ip).version==4]
try:
 s=socket.create_connection(('127.0.0.1',18781),2);s.close();tunnel=True
except OSError:tunnel=False
print(json.dumps({'permitted':permitted,'relay_ip':ips[0] if ips else None,'tunnel_up':tunnel}))
