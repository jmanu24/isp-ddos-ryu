"""Fixed statistical design, separate from immutable benign plans."""
import ipaddress
SCENARIOS={'benign_off':('B0','baseline'),'benign_on':('B0','enabled'),'attack_off':('B0+attack','baseline'),'attack_on':('B0+attack','enabled')}
def scenario_steps(reference,scenario,start_s=300,end_s=360,source_ips=None,description=''):
 if scenario not in SCENARIOS:raise ValueError('Unknown experimental scenario')
 attack=scenario.startswith('attack_');sources=[]
 if attack:
  if not 0<=start_s<end_s<=600:raise ValueError('Attack window must be within 0–600 seconds')
  if not source_ips or not description.strip():raise ValueError('Declare attack source IPs and repeatable attack conditions')
  for raw in source_ips:
   ip=ipaddress.ip_address(raw)
   if ip.version!=4 or not ip.is_private:raise ValueError('Attack source must be a private laboratory IPv4 address')
   sources.append(str(ip))
 mode,pipeline=SCENARIOS[scenario]
 return [dict(r,scenario=mode,pipeline=pipeline,attack_windows=[dict(name='external_attack',start_s=start_s,end_s=end_s)] if attack else []) for r in reference],sorted(set(sources))
