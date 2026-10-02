"""Install the IPoE boot guard on the inventory BNG, using existing lab credentials."""
import sys,os,subprocess
from pathlib import Path
lab=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(lab))
from webtool.inventory import credentials_for,NODES
u,p=credentials_for('bng');node=next(n for n in NODES if n.name=='bng');env=dict(os.environ,SSHPASS=p)
source=lab/'ansible/roles/bng/files/ensure_ipoe_module.sh'
ssh=['sshpass','-e','ssh','-T','-o','StrictHostKeyChecking=yes',u+'@'+node.ip]
subprocess.run(['sshpass','-e','scp','-o','StrictHostKeyChecking=yes',str(source),u+'@'+node.ip+':/tmp/ensure_ipoe_module.sh'],env=env,check=True)
command="set -eu; sudo -n install -m 0755 /tmp/ensure_ipoe_module.sh /usr/local/sbin/ensure-ipoe-module; sudo -n /usr/local/sbin/ensure-ipoe-module; sudo -n mkdir -p /etc/systemd/system/accel-pppd.service.d; printf '[Service]\\nExecStartPre=/usr/local/sbin/ensure-ipoe-module\\n' | sudo -n tee /etc/systemd/system/accel-pppd.service.d/ipoe-kernel.conf >/dev/null; sudo -n systemctl daemon-reload; sudo -n systemctl restart accel-pppd; sudo -n systemctl is-active accel-pppd; modinfo -F vermagic ipoe"
subprocess.run(ssh+[command],env=env,check=True)
