"""Validate completed evidence, reconcile live mappings and apply references."""
from pathlib import Path
exec((Path('/home/ubuntu/isp-ddos-ryu/deploy/vm-lab/tools/benign-lab/scripts/calibrate_capacity.py')).read_text().split('report_path=')[0])
import hashlib
report_path=REPORT/'measurements.json'
report=json.loads(report_path.read_text())
state=ssh(NODES_BY_NAME['orchestrator'].ip,credentials_for('orchestrator')[0],'systemctl is-active ryu-manager.service; systemctl show ryu-manager.service -p Environment')
if 'active' not in state.splitlines() or 'LAB_CALIBRATION_MODE=true' in state:
    raise RuntimeError('Normal controller mode must be restored before applying references')
flows=ssh(NODES_BY_NAME['pe'].ip,credentials_for('pe')[0],'ovs-ofctl -O OpenFlow13 dump-flows br-ent')
if 'cookie=0xbe910090' in flows:
    raise RuntimeError('Temporary calibration forwarding rules remain')
report['cleanup_verified']=dict(ryu_service='active',calibration_mode=False,temporary_flow_cookie_present=False)
probe_hash=hashlib.sha256(PROBE.encode()).hexdigest()
if report.get('probe_sha256')!=probe_hash:
    raise RuntimeError('Evidence does not match the frozen probe')
summary={}
for domain in domains:
    values={}
    for direction in ('ul','dl'):
        rows=[r for r in report['rounds'] if r['domain']==domain and r['direction']==direction]
        if len(rows)<3 or any(r['probe_sha256']!=probe_hash or r['mbps']<=0 or len(r['sources'])!=len(domains[domain]) for r in rows):
            raise RuntimeError('Incomplete evidence for '+domain+' '+direction)
        rates=[r['mbps'] for r in rows]
        errors=[dict(node=source['node'],repeat=r['repeat'],error=stream['error']) for r in rows for source in r['sources'] for stream in source['streams'] if stream.get('error')]
        values[direction]=dict(median_mbps=statistics.median(rates),min_mbps=min(rates),max_mbps=max(rates),repetitions=len(rows),stream_errors=errors)
    reference=round(min(values['ul']['median_mbps'],values['dl']['median_mbps']),2)
    if report['capacity_mbps'][domain]!=reference:
        raise RuntimeError('Reference calculation mismatch')
    summary[domain]=dict(reference_mbps=reference,directions=values)
report['summary']=summary
ric=json.loads((REPORT/'ric-status-during-calibration.json').read_text())
if len(ric.get('enforced',{}))!=5 or any(value.get('action')!='unblock' or value.get('max_prb')!=100 for value in ric['enforced'].values()):
    raise RuntimeError('Mobile must have five unthrottled DU/UE contexts')
report['mobile_actuation_check']=dict(enforced_records=5,all_actions='unblock',all_max_prb=100,evidence='RIC /status snapshot taken during final Mobile calibration')
report['completed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
report['limitations']=['TCP payload goodput with these Python generators; not physical link capacity or UDP loss capacity.', 'Domains measured separately; references do not guarantee simultaneous peaks.', 'Enterprise used calibration-only data-plane forwarding rules.', 'Any TCP reset is reported; its partial received bytes are divided by the full 8s measurement window, including the outage.', 'Observed variability and VM scheduling are retained in the directional ranges.']
config_path=APP/'config/lab.connected.yaml'
backup=PRIVATE/'lab.before-calibration.yaml'
if not backup.exists(): backup.write_text(config_path.read_text())
current_ips={}
for domain,items in domains.items():
    for name,node in items:
        prefix='sudo -n ip netns exec '+shlex.quote(node['namespace'])+' ' if node.get('namespace') else ''
        addresses=json.loads(ssh(node['host'],node['user'],prefix+'ip -j -4 address show dev '+shlex.quote(node['interface'])))
        ips=[address['local'] for interface in addresses for address in interface['addr_info'] if address['family']=='inet']
        if len(ips)!=1: raise RuntimeError('Ambiguous or missing data address for '+name)
        routes=json.loads(ssh(node['host'],node['user'],prefix+'ip -j route get 10.55.0.100 from '+ips[0]))
        if routes[0]['dev']!=node['interface']: raise RuntimeError('Wrong route for '+name)
        node['source_ip']=ips[0]
        current_ips[name]=ips[0]
sessions=ssh(NODES_BY_NAME['bng'].ip,'labadmin','sudo -n accel-cmd -p 2000 show sessions')
session_ips={line.split('|')[3].strip() for line in sessions.splitlines() if ' | ipoe |' in line and 'active' in line}
fixed_ips={node['source_ip'] for name,node in domains['fixed']}
if len(session_ips)!=10 or session_ips!=fixed_ips:
    raise RuntimeError('Configured Fixed addresses must match ten active BNG sessions')
report['applied_source_ips']=current_ips
CFG['capacity_mbps']=report['capacity_mbps']
CFG['capacity_calibration']=dict(report='docs/CAPACITY_MEASUREMENTS.json',timestamp=report['completed_utc'],probe_sha256=probe_hash,unit='TCP delivered payload Mbps',selection=report['selection'])
CFG['deployment_pending']=[]
CFG['controller']['access']='web on management IP 192.168.18.154:8780; all worker SSH originates here'
config_path.write_text(yaml.safe_dump(CFG,sort_keys=False))
(APP/'docs/CAPACITY_MEASUREMENTS.json').write_text(json.dumps(report,indent=2))
report_path.write_text(json.dumps(report,indent=2))
readme=ROOT/'deploy/vm-lab/README.md'
text=readme.read_text().replace('Set the four domain capacities in `config/lab.connected.yaml`\nbefore running a scientific baseline.', 'The four domain capacities in `config/lab.connected.yaml` were measured\nexperimentally; see `tools/benign-lab/docs/CAPACITY_CALIBRATION.md` and its\nraw `CAPACITY_MEASUREMENTS.json` report before interpreting a baseline.')
readme.write_text(text)
deployment=APP/'docs/CONNECTED_DEPLOYMENT.md'
with deployment.open('a') as stream:
    stream.write('\n## Applied experimental capacities\n\nThe capacity placeholders were completed using the frozen TCP calibration\nprobe. `CAPACITY_MEASUREMENTS.json` contains all samples and limitations.\nThe applied references in Mbps are: '+json.dumps(report['capacity_mbps'])+'.\nFixed source addresses were reconciled with ten active IPoE sessions.\nCalibration forwarding rules and the temporary controller mode were removed.\n')
subprocess.run(['sudo','systemctl','restart','benign-lab-web.service'],check=True)
print(json.dumps(summary,indent=2))
