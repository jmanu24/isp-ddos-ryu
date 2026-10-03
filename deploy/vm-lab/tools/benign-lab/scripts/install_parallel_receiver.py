import os,subprocess,sys,shlex,argparse
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description='Install the persistent Victim receiver from the control node')
    p.add_argument('--workers',type=int,default=4);a=p.parse_args()
    if not 1<=a.workers<=64:p.error('workers must be 1..64')
    root=Path(__file__).resolve().parents[5]
    sys.path.insert(0,str(root/'deploy/vm-lab'))
    from webtool.inventory import credentials_for
    user,password=credentials_for('victim');env=os.environ.copy();env['SSHPASS']=password
    base=['sshpass','-e','ssh','-T','-o','StrictHostKeyChecking=yes',user+'@10.10.0.100']
    subprocess.run(base+['mkdir -p /opt/benign-lab'],env=env,check=True)
    agent=Path(__file__).resolve().parents[1]/'benign_lab/agent.py'
    for filename in ('connection_pool.py','agent.py'):
        source=agent.with_name(filename)
        subprocess.run(['sshpass','-e','scp','-o','StrictHostKeyChecking=yes',str(source),user+'@10.10.0.100:/opt/benign-lab/'+filename],env=env,check=True)
    service='''#!/sbin/openrc-run
description="BENIGN Lab receiver"
command="/usr/bin/python3"
command_args="/opt/benign-lab/agent.py receiver --host 10.55.0.100 --workers %s"
command_background="yes"
pidfile="/run/benign-lab-receiver.pid"
depend() { need net; }
'''%a.workers
    cmd="printf %%s %s > /etc/init.d/benign-lab-receiver; chmod 755 /etc/init.d/benign-lab-receiver; rc-update add benign-lab-receiver default; rc-service benign-lab-receiver restart"%shlex.quote(service)
    subprocess.run(base+[cmd],env=env,check=True)

if __name__=='__main__':main()
