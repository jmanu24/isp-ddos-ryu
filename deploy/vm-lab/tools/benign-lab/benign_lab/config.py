from __future__ import annotations
import fnmatch
import hashlib
import ipaddress
import json
import re
import shlex
import sys
from pathlib import Path
import yaml
from .planner import canonical

ROOT = Path(__file__).resolve().parent.parent


def load_lab(path):
    cfg = yaml.safe_load(Path(path).read_text())
    if not isinstance(cfg,dict) or not cfg.get('nodes') or not cfg.get('targets'):
        raise ValueError('lab.yaml requires nodes and targets')
    return cfg


def node_for(cfg, source):
    if source in cfg['nodes']:
        return cfg['nodes'][source]
    matches = [v for k,v in cfg['nodes'].items() if fnmatch.fnmatchcase(source,k)]
    if len(matches) != 1:
        raise ValueError(f'Missing or ambiguous node mapping: {source}')
    return matches[0]


def command(node, supervisor=False):
    adapter = node.get('adapter','local')
    if adapter not in ('local','netns','ssh','ssh_netns'):
        raise ValueError(f'Unknown adapter {adapter}')
    remote = adapter.startswith('ssh')
    python = node.get('python','python3' if remote else sys.executable)
    agent = node.get('agent_path','/opt/benign-lab/benign_lab/agent.py' if remote else str(ROOT/'benign_lab/agent.py'))
    inner = [python,agent,'worker']
    if supervisor:
        agent=node.get('supervisor_path',str(Path(agent).with_name('supervisor.py')))
        inner=[python,agent,'supervisor']
        if adapter in ('netns','ssh_netns') and node.get('sudo',False):
            inner=['sudo','-n',*inner]
    elif adapter in ('netns','ssh_netns'):
        namespace = node.get('namespace','')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',namespace):
            raise ValueError('Invalid namespace')
        inner = ['ip','netns','exec',namespace,*inner]
        if node.get('sudo',False): inner = ['sudo','-n',*inner]
    if not remote:
        return inner
    host = node.get('host') or ''
    user = node.get('user') or ''
    if not re.fullmatch(r'[A-Za-z0-9_.:@-]+',host) or host.startswith('-') or not re.fullmatch(r'[A-Za-z0-9_.-]+',user) or user.startswith('-'):
        raise ValueError('Invalid SSH host/user')
    args = ['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2','-p',str(int(node.get('port',22)))]
    if node.get('identity_file'): args += ['-i',node['identity_file']]
    if node.get('known_hosts_file'): args += ['-o','UserKnownHostsFile='+node['known_hosts_file']]
    if node.get('auth_mode')=='password_env':
        args=[sys.executable,str(ROOT/'benign_lab/ssh_bridge.py'),'--password-env',node.get('password_env','BENIGN_SSH_PASSWORD'),'--',*args]
    downstream=[*args,f'{user}@{host}',shlex.join(inner)]
    jump=node.get('control_node')
    if jump:
        # Execute the password bridge on the control node: credentials never cross stdout.
        remote_args=['python3',node.get('bridge_path','/home/ubuntu/benign-lab/benign_lab/ssh_bridge.py'),'--credentials',node.get('credentials_file','/home/ubuntu/.config/benign-lab/ssh.json'),'--',
                     'ssh','-T','-o','BatchMode=no','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+node.get('remote_known_hosts_file','/home/ubuntu/.config/benign-lab/known_hosts'),'-o','ConnectTimeout=8',f'{user}@{host}',shlex.join(inner)]
        outer=['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8']
        if node.get('control_identity_file'): outer+=['-i',node['control_identity_file'],'-o','IdentitiesOnly=yes']
        return [*outer,jump,shlex.join(remote_args)]
    return downstream


def peering_assignments(cfg, plan):
    pool=cfg.get('peering_pool')
    if not pool:return {}
    if pool.get('strategy')!='logical_source_round_robin_v1':
        raise ValueError('Unsupported Peering assignment strategy')
    members=pool.get('members',[])
    if len(members)<2 or len(set(members))!=len(members):
        raise ValueError('Peering pool requires distinct members')
    nodes=[cfg['nodes'][name] for name in members]
    if len({n.get('source_ip') for n in nodes})!=len(nodes):
        raise ValueError('Peering members require distinct source IPs')
    sources=sorted({e['source'] for e in plan['events'] if e['domain']=='peering'})
    return {source:members[i%len(members)] for i,source in enumerate(sources)}


def resolve(cfg, plan):
    groups = {}
    assignments=peering_assignments(cfg,plan)
    if cfg.get('require_explicit_mapping'):
        issues = mapping_issues(cfg)
        if issues: raise ValueError('Incomplete laboratory mapping: ' + '; '.join(issues))
        if cfg.get('require_matching_plan_capacities',False) and cfg.get('capacity_mbps') != plan['capacity_mbps']:
            raise ValueError('Strict capacity policy: plan capacities differ from the laboratory reference')
    networks = [ipaddress.ip_network(x) for x in cfg.get('allowed_target_cidrs',['127.0.0.0/8','10.0.0.0/8'])]
    for event in plan['events']:
        node = executor_for(cfg,event,assignments)
        argv = command(node)
        target = cfg['targets'].get(event['destination'])
        if target is None:
            raise ValueError(f"Missing target {event['destination']}")
        try: address = ipaddress.ip_address(target['host'])
        except ValueError: raise ValueError('Target host must be an IP address for reproducible routing')
        if not any(address in net for net in networks):
            raise ValueError(f'Target {address} outside allowed laboratory CIDRs')
        for key in ('tcp_port','udp_port','http_port'):
            if not 1 <= int(target[key]) <= 65535: raise ValueError(f'Invalid {key}')
        context = {k:node.get(k) for k in ('source_ip','interface','expected_gateway','check_route','session_id','access_mode','domain')}
        if node.get('executor_name'):
            context.update(source_as=node.get('source_as'),executor_name=node['executor_name'])
        key = hashlib.sha256(canonical([argv,context])).hexdigest()[:12]
        groups.setdefault(key,dict(argv=argv,node=node,context=context,events=[],sources=set()))
        groups[key]['events'].append(event)
        groups[key]['sources'].add(event['source'])
    return groups


def supervisor_groups(groups):
    """Share only identical host/security/interpreter supervisor commands."""
    sessions={}
    for key,group in groups.items():
        argv=command(group['node'],supervisor=True)
        sid=hashlib.sha256(canonical(argv)).hexdigest()[:12]
        node=dict(group['node'])
        node['adapter']='netns' if node.get('adapter') in ('netns','ssh_netns') else 'local'
        child=command(node)
        # The namespace supervisor already runs as root, matching the old
        # privileged namespace worker without a second sudo process.
        if node['adapter']=='netns' and node.get('sudo') and child[:2]==['sudo','-n']:
            child=child[2:]
        sessions.setdefault(sid,dict(argv=argv,workers=[]))['workers'].append(dict(key=key,argv=child,group=group))
    return sessions


def executor_for(cfg, event, assignments=None):
    """Domain contract: network provisioning belongs to the laboratory."""
    member=(assignments or {}).get(event['source']) if event['domain']=='peering' else None
    node = dict(cfg['nodes'][member] if member else node_for(cfg, event['source']))
    if member:node['executor_name']=member
    domain = event['domain']
    node['domain'] = domain
    strict = cfg.get('require_explicit_mapping', False)
    if strict:
        if not node.get('configured', False):
            raise ValueError(f"Complete and enable node mapping: {event['source']}")
        if node.get('adapter') not in ('local','netns','ssh','ssh_netns'):
            raise ValueError('Explicit adapter required')
        if not node.get('source_ip') or not node.get('interface'):
            raise ValueError(f"source_ip and interface required: {event['source']}")
        if domain == 'mobile' and node['adapter'] not in ('netns','ssh_netns'):
            raise ValueError('Mobile must execute inside a UE namespace')
        if domain == 'fixed':
            if node.get('access_mode') not in ('ipoe_namespace','ipoe_bound') or not node.get('session_id'):
                raise ValueError('Fixed requires an existing IPoE session_id and access_mode')
            if node['access_mode'] == 'ipoe_namespace' and node['adapter'] not in ('netns','ssh_netns'):
                raise ValueError('ipoe_namespace requires a namespace adapter')
        if domain == 'peering' and not node.get('expected_gateway'):
            raise ValueError('Peering requires the peer-router data-plane gateway')
        node['check_route'] = True
    for field in ('source_ip','expected_gateway'):
        if node.get(field):
            ipaddress.IPv4Address(node[field])
    if node.get('interface') and not re.fullmatch(r'[A-Za-z0-9_.:-]+', node['interface']):
        raise ValueError('Invalid data-plane interface')
    return node


def mapping_issues(cfg):
    """Read-only inventory; nulls are unresolved parameters, never sample addresses."""
    if not cfg.get('require_explicit_mapping'): return []
    issues=[]
    for d in ('mobile','fixed','enterprise','peering'):
        v=cfg.get('capacity_mbps',{}).get(d)
        if not isinstance(v,(int,float)) or not .01<=v<=10000:
            issues.append(f'capacity_mbps.{d}')
    for source,node in cfg['nodes'].items():
        fields=['source_ip','interface']
        if not node.get('configured'): issues.append(f'nodes.{source}.configured')
        if node.get('adapter','').startswith('ssh'): fields+=['host','user']
        if node.get('adapter') in ('netns','ssh_netns'): fields+=['namespace']
        if source.startswith('fixed'): fields+=['session_id','access_mode']
        if source.startswith('peer-'): fields+=['expected_gateway']
        for field in fields:
            if not node.get(field): issues.append(f'nodes.{source}.{field}')
    for target,value in cfg['targets'].items():
        if not value.get('host'): issues.append(f'targets.{target}.host')
    return issues
