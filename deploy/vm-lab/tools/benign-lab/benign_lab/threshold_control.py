"""Validated, explicit threshold updates on the real orchestrator."""
import json
from .baseline import BaselineGuard

FIELDS={'DECISION_THRESHOLD','SYN_THRESHOLD','UDP_THRESHOLD','ICMP_THRESHOLD','DIST_PPS_THRESHOLD'}

class ThresholdControl:
    def __init__(self,cfg):self.guard=BaselineGuard(cfg,'threshold-control',0)
    async def read(self):
        code="""import ast,json,hashlib
from pathlib import Path
p=Path('/opt/Tesis_Controller/config/settings.py');text=p.read_text();values={}
for n in ast.parse(text).body:
 if isinstance(n,ast.Assign):
  for t in n.targets:
   if isinstance(t,ast.Name) and t.id in FIELDS:values[t.id]=ast.literal_eval(n.value)
print(json.dumps(dict(values=values,config_sha256=hashlib.sha256(text.encode()).hexdigest())))
""".replace('FIELDS',repr(FIELDS))
        return json.loads(await self.guard.controller(code))
    async def apply(self,values,expected_hash):
        if not values or set(values)-FIELDS:raise ValueError('Unsupported threshold fields')
        import math
        if any(isinstance(v,bool) or not isinstance(v,(float,int)) or not math.isfinite(v) or not 0<v<=1000000 for v in values.values()):raise ValueError('Thresholds must be finite positive numbers')
        code="""import hashlib,json,os,re,subprocess,time,socket,ast
from pathlib import Path
p=Path('/opt/Tesis_Controller/config/settings.py');old=p.read_text();expected=EXPECTED;values=VALUES
if hashlib.sha256(old.encode()).hexdigest()!=expected:raise RuntimeError('Threshold configuration changed; reload before applying')
lease=Path('/run/benign-baseline/lease.json')
if lease.exists() and json.loads(lease.read_text()).get('expires_at',0)>time.time():raise RuntimeError('A baseline lease is active')
current={}
for node in ast.parse(old).body:
 if isinstance(node,ast.Assign):
  for target in node.targets:
   if isinstance(target,ast.Name) and target.id in values:current[target.id]=ast.literal_eval(node.value)
if all(current.get(name)==value for name,value in values.items()):
 print(json.dumps(dict(applied=values,config_sha256=hashlib.sha256(old.encode()).hexdigest(),controller_restarted=False,changed=False)));raise SystemExit(0)
text=old
for name,value in values.items():
 text,count=re.subn(r'^'+re.escape(name)+r'\\s*=.*$',name+' = '+repr(value),text,flags=re.M)
 if count!=1:raise RuntimeError('Threshold assignment is ambiguous: '+name)
compile(text,str(p),'exec')
if text==old:
 print(json.dumps(dict(applied=values,config_sha256=hashlib.sha256(old.encode()).hexdigest(),controller_restarted=False,changed=False)));raise SystemExit(0)
st=p.stat()
def write(content):
 tmp=p.with_suffix('.audit.tmp');tmp.write_text(content);os.chmod(str(tmp),st.st_mode);os.chown(str(tmp),st.st_uid,st.st_gid);tmp.replace(p)
backup=Path('/var/lib/benign-threshold-history');backup.mkdir(mode=0o700,exist_ok=True);(backup/(str(time.time_ns())+'.py')).write_text(old)
write(text)
try:
 subprocess.run(['systemctl','restart','ryu-manager'],check=True,timeout=20)
 for _ in range(12):
  time.sleep(1)
  try:
   socket.create_connection(('127.0.0.1',6653),1).close();break
  except OSError:pass
 else:raise RuntimeError('Controller did not resume')
except Exception:
 write(old);subprocess.run(['systemctl','restart','ryu-manager'],timeout=20);raise RuntimeError('Threshold update failed; previous configuration restored')
print(json.dumps(dict(applied=values,config_sha256=hashlib.sha256(text.encode()).hexdigest(),controller_restarted=True)))
""".replace('EXPECTED',repr(expected_hash)).replace('VALUES',repr(values))
        return json.loads(await self.guard.ssh(self.guard.control['host'],self.guard.control['user'],'python3 -',root=True,payload=code,timeout=60))
