"""Provision an Alpine lab gateway that carries the lab VLANs as VXLAN directly over the Ethernet link (no WireGuard)."""
import argparse,json,subprocess,os,re
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--role',choices=['relay','gateway'],required=True);p.add_argument('--mac-map',required=True);p.add_argument('--trunk-mac',required=True,help='MAC of the NIC attached to the direct Ethernet link');a=p.parse_args()
assert os.geteuid()==0,'Run on the gateway as root'
assert Path('/etc/hostname').read_text().strip()=='lab-wifi-'+a.role,'Refusing to configure a production node'
mapping=json.loads(Path(a.mac_map).read_text());trunk='wired0' if a.role=='relay' else 'trunk0'
assert set(mapping.values())-{trunk}=={'eth'+str(i) for i in range(8)}
b=Path('/etc/lab-overlay');b.mkdir(exist_ok=True);(b/'mac-names.json').write_text(json.dumps(mapping))
selfip,peerip,mgmt=('172.31.252.1','172.31.252.2','10.10.0.252') if a.role=='relay' else ('172.31.252.2','172.31.252.1','10.10.0.253')
for name,value in [('self',selfip),('peer',peerip),('management',mgmt)]: (b/name).write_text(value+'\n')
trunk_mac=a.trunk_mac.lower();assert re.fullmatch(r'([0-9a-f]{2}:){5}[0-9a-f]{2}',trunk_mac),'Invalid trunk MAC'
(b/'trunk-mac').write_text(trunk_mac+'\n');(b/'trunk-name').write_text(trunk+'\n')
rename='''import json,subprocess,time
from pathlib import Path
m=json.loads(Path('/etc/lab-overlay/mac-names.json').read_text())
m[Path('/etc/lab-overlay/trunk-mac').read_text().strip()]=Path('/etc/lab-overlay/trunk-name').read_text().strip()
for retry in range(15):
 rows=json.loads(subprocess.check_output(['ip','-j','link'],text=True));found={r.get('address','').lower():r['ifname'] for r in rows}
 if all(mac in found for mac in m):break
 time.sleep(1)
else:raise RuntimeError('Expected laboratory NIC missing')
for i,(mac,target) in enumerate(m.items()):
 subprocess.run(['ip','link','set',found[mac],'down'],check=True)
 subprocess.run(['ip','link','set',found[mac],'name','labtmp'+str(i)],check=True)
for i,(mac,target) in enumerate(m.items()):subprocess.run(['ip','link','set','labtmp'+str(i),'name',target],check=True)
'''
(b/'rename_interfaces.py').write_text(rename)
svc=Path('/etc/init.d/lab-ifnames');svc.write_text('#!/sbin/openrc-run\ndepend() { need localmount; before networking; }\nstart() { ebegin "Mapping laboratory NICs"; /usr/bin/python3 /etc/lab-overlay/rename_interfaces.py >>/var/log/lab-ifnames.log 2>&1; eend $?; }\n');svc.chmod(0o755)
for level in ['boot','default']:
 link=Path('/etc/runlevels')/level/'lab-ifnames'
 if os.path.lexists(link):link.unlink()
Path('/etc/runlevels/boot/lab-ifnames').symlink_to('/etc/init.d/lab-ifnames')
overlay='''#!/bin/sh
set -eu
T=$(cat /etc/lab-overlay/trunk-name)
SELF=$(cat /etc/lab-overlay/self)
PEER=$(cat /etc/lab-overlay/peer)
ip link set "$T" mtu 1600
ip link set "$T" up
ip address replace "$SELF/30" dev "$T"
i=1
for vid in 800 801 804 805 806 807 808; do
 br=br$vid; vx=vx$vid
 ip link show "$br" >/dev/null 2>&1 || ip link add "$br" type bridge stp_state 0
 ip link set "$br" up
 ip link show "$vx" >/dev/null 2>&1 || ip link add "$vx" type vxlan id "$vid" local "$SELF" remote "$PEER" dev "$T" dstport 4789 nolearning df unset
 ip link set "$vx" mtu 1500
 ip link set "$vx" master "$br"
 ip link set "$vx" up
 ip link set "eth$i" master "$br"
 ip link set "eth$i" up
 i=$((i+1))
done
ip address replace "$(cat /etc/lab-overlay/management)/24" dev br800
'''
script=Path('/etc/local.d/lab-overlay.start');script.write_text(overlay);script.chmod(0o755)
subprocess.run(['rc-update','add','local','default'],check=True)
print('Gateway configuration saved; apply on next boot')
