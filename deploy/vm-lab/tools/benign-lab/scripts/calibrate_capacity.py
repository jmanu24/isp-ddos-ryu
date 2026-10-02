"""Sequential domain calibration; aggregate concurrent real source contexts."""
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import statistics
import subprocess
import sys
import time
import yaml

ROOT=Path('/home/ubuntu/isp-ddos-ryu')
APP=ROOT/'deploy/vm-lab/tools/benign-lab'
PRIVATE=ROOT/'.runtime/benign-lab'
sys.path.insert(0,str(ROOT/'deploy/vm-lab'))
from webtool.inventory import credentials_for, NODES_BY_NAME
CFG=yaml.safe_load((APP/'config/lab.connected.yaml').read_text())
PASSWORD=json.loads((PRIVATE/'ssh.json').read_text())['password']
PROBE=(APP/'scripts/capacity_probe.py').read_text()
REPORT=PRIVATE/'calibration'
REPORT.mkdir(exist_ok=True)

def ssh(host,user,command,payload=None,timeout=35):
    password=credentials_for('pe')[1] if host==NODES_BY_NAME['pe'].ip else (credentials_for('victim')[1] if user=='root' else (credentials_for('orchestrator')[1] if host==NODES_BY_NAME['orchestrator'].ip else PASSWORD))
    env=os.environ.copy();env['SSHPASS']=password
    proc=subprocess.run(['sshpass','-e','ssh','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(PRIVATE/'known_hosts'),'-o','ConnectTimeout=5',user+'@'+host,command],input=payload,env=env,capture_output=True,text=True,timeout=timeout)
    if proc.returncode:
        raise RuntimeError(host+': '+proc.stderr[-500:]+proc.stdout[-500:])
    return proc.stdout

domains={
    'mobile':[('ue'+str(i),CFG['nodes']['ue'+str(i)]) for i in range(1,6)],
    'fixed':[('fixed'+str(i),CFG['nodes']['fixed'+str(i)]) for i in range(1,11)],
    'enterprise':[('ent-site-'+str(i),CFG['nodes']['ent-site-'+str(i)]) for i in range(1,6)],
    'peering':[('peer-flow*',CFG['nodes']['peer-flow*'])],
}

def client(item,direction,streams):
    name,node=item
    addresses=json.loads(ssh(node['host'],node['user'],('sudo -n ip netns exec '+shlex.quote(node['namespace'])+' ' if node.get('namespace') else '')+'ip -j -4 address show dev '+shlex.quote(node['interface'])))
    candidates=[address['local'] for interface in addresses for address in interface['addr_info'] if address['family']=='inet']
    if not candidates:
        raise RuntimeError('No IPv4 data address for '+name)
    node['source_ip']=candidates[0]
    route='ip -j route get 10.55.0.100 from '+node['source_ip']
    prefix='sudo -n ip netns exec '+shlex.quote(node['namespace'])+' ' if node.get('namespace') else ''
    command=prefix+route
    routes=json.loads(ssh(node['host'],node['user'],command))
    if routes[0]['dev']!=node['interface']:
        raise RuntimeError('Wrong data interface for '+name)
    args=['python3','/tmp/benign-capacity-probe.py','client','--source',node['source_ip'],'--direction',direction,'--streams',str(streams)]
    result=json.loads(ssh(node['host'],node['user'],prefix+' '.join(map(shlex.quote,args))))
    result['node']=name;result['route']=routes
    return result

report_path=REPORT/'measurements.json'
if '--fresh' in sys.argv and report_path.exists():
    report_path.rename(REPORT/('measurements-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'.json'))
report=json.loads(report_path.read_text()) if report_path.exists() else dict(timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),method='TCP aggregate delivered payload goodput, 10s rounds / 2s discarded warmup, victim 10.55.0.100, sequential domains, UL/DL separate',scope='Achievable end-to-end goodput with these VM generators, not physical link capacity',rounds=[],capacity_mbps={})
probe_hash=hashlib.sha256(PROBE.encode()).hexdigest()
if report['rounds'] and report.get('probe_sha256')!=probe_hash:
    raise RuntimeError('Probe version changed; pass --fresh to start an independent campaign')
report['probe_sha256']=probe_hash
hosts={(node['host'],node['user']) for values in domains.values() for _,node in values}
for host,user in sorted(hosts|{('10.10.0.100','root')}):
    ssh(host,user,'cat > /tmp/benign-capacity-probe.py',PROBE)
server_pid=None
calibration_enabled=False
pe_rules=False
controller_user=credentials_for('orchestrator')[0]
controller_host=NODES_BY_NAME['orchestrator'].ip
override='/run/systemd/system/ryu-manager.service.d/benign-calibration.conf'
restore='rm -f '+override+'; systemctl daemon-reload; systemctl restart ryu-manager.service'
try:
    if '--without-mitigation' not in sys.argv:
        raise RuntimeError('Pass --without-mitigation for a bounded calibration session with automatic restoration')
    ssh(controller_host,controller_user,'sudo -n systemd-run --unit=benign-calibration-restore --on-active=15m /bin/sh -c '+shlex.quote(restore))
    calibration_enabled=True
    ssh(controller_host,controller_user,'sudo -n mkdir -p /run/systemd/system/ryu-manager.service.d && printf '+shlex.quote('[Service]\nEnvironment=LAB_CALIBRATION_MODE=true\n')+' | sudo -n tee '+override+' >/dev/null && sudo -n systemctl daemon-reload && sudo -n systemctl restart ryu-manager.service')
    state=ssh(controller_host,controller_user,'systemctl show ryu-manager.service -p Environment; systemctl is-active ryu-manager.service')
    if 'LAB_CALIBRATION_MODE=true' not in state or 'active' not in state:
        raise RuntimeError('Controller calibration mode was not activated')
    # Re-establish leases whose server-side session was terminated by mitigation.
    refresh="""import json,subprocess
addresses=[]
for n in range(1,11):
    addresses.extend(json.loads(subprocess.check_output(['ip','-n','fixed%d'%n,'-j','-4','address'])))
with open('/run/bng-agent/cmd','w') as fifo:
    for interface in addresses:
        if interface['ifname'].startswith('macvlan'):
            for address in interface['addr_info']:
                if address['family']=='inet':
                    fifo.write('kick '+address['local']+'\\n')
                    fifo.flush()
"""
    ssh('10.10.0.9','labadmin','sudo -n python3 -',refresh)
    for attempt in range(30):
        sessions=ssh(NODES_BY_NAME['bng'].ip,'labadmin','sudo -n accel-cmd -p 2000 show sessions')
        if sum(' | ipoe |' in line and 'active' in line for line in sessions.splitlines())==10:
            break
        time.sleep(3)
    else:
        raise RuntimeError('Ten active IPoE sessions required before calibration')
    report['mitigation']='Temporarily suspended using LAB_CALIBRATION_MODE, forwarding and telemetry retained; finally restoration plus 15 minute watchdog'
    # Avoid table-miss packet processing becoming the capacity benchmark.
    pe_user=credentials_for('pe')[0]
    pe_host=NODES_BY_NAME['pe'].ip
    pe_rules=True
    for rule in ('in_port=3,nw_src=10.70.0.0/24,nw_dst=10.55.0.100,tp_dst=19090,actions=output:5','in_port=5,nw_src=10.55.0.100,nw_dst=10.70.0.0/24,tp_src=19090,actions=output:3'):
        ssh(pe_host,pe_user,'ovs-ofctl -O OpenFlow13 add-flow br-ent '+shlex.quote('cookie=0xbe910090,hard_timeout=900,priority=20,tcp,'+rule))
    report['enterprise_forwarding']='Temporary TCP calibration-only rules between Enterprise 10.70.0.0/24 and victim 10.55.0.100 on br-ent, in_port 3 <-> 5, priority 20 below mitigation priority 100, cookie 0xbe910090, 900s expiry; removed at cleanup'
    command='nohup python3 /tmp/benign-capacity-probe.py server > /tmp/benign-capacity-server.log 2>&1 < /dev/null & echo $!'
    server_pid=int(ssh('10.10.0.100','root',command).strip().splitlines()[-1])
    time.sleep(1)
    for domain in ('enterprise','peering','mobile','fixed'):
        items=domains[domain]
        for direction in ('ul','dl'):
            for repeat in range(1,6):
                initial=[r['mbps'] for r in report['rounds'] if r['domain']==domain and r['direction']==direction and r['repeat']<=3]
                unstable=len(initial)==3 and min(initial)>0 and max(initial)/min(initial)>1.3
                if repeat>=4 and not unstable:
                    continue
                if any(r['domain']==domain and r['direction']==direction and r['repeat']==repeat for r in report['rounds']):
                    continue
                with concurrent.futures.ThreadPoolExecutor(max_workers=len(items)) as pool:
                    values=list(pool.map(lambda item:client(item,direction,2),items))
                result=dict(domain=domain,direction=direction,repeat=repeat,streams_per_source=2,mbps=sum(x['mbps'] for x in values),sources=values,probe_sha256=probe_hash)
                report['rounds'].append(result)
                (REPORT/'measurements.json').write_text(json.dumps(report,indent=2))
                print(json.dumps({key:value for key,value in result.items() if key!='sources'}),flush=True)
                time.sleep(1)
        medians={direction:statistics.median(r['mbps'] for r in report['rounds'] if r['domain']==domain and r['direction']==direction) for direction in ('ul','dl')}
        report['capacity_mbps'][domain]=round(min(medians.values()),2)
        print(json.dumps(dict(domain=domain,medians=medians,reference_mbps=report['capacity_mbps'][domain])),flush=True)
    report['selection']='Minimum of directional medians; three initial repeats per direction, optional two additional repeats when initial max/min exceeds 1.3. Scalar reference accommodates BENIGN_V1 bidirectional traffic conservatively.'
    (REPORT/'measurements.json').write_text(json.dumps(report,indent=2))
finally:
    try:
        try:
            if server_pid:
                print('receiver diagnostics: '+ssh('10.10.0.100','root','tail -10 /tmp/benign-capacity-server.log'),flush=True)
                ssh('10.10.0.100','root','kill '+str(server_pid))
        finally:
            if pe_rules:
                ssh(pe_host,pe_user,'ovs-ofctl -O OpenFlow13 del-flows br-ent '+shlex.quote('cookie=0xbe910090/-1'))
    finally:
        if calibration_enabled:
            ssh(controller_host,controller_user,'sudo -n /bin/sh -c '+shlex.quote(restore))
            ssh(controller_host,controller_user,'sudo -n systemctl stop benign-calibration-restore.timer')
            print('Normal detection restored.',flush=True)
