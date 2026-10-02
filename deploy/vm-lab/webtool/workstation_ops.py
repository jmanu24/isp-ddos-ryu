"""VMware Player backend for selected migrated VMs over a loopback SSH tunnel."""
import json,os,urllib.request
from pathlib import Path
def config():
 p=Path(os.environ.get('BENIGN_WORKSTATION_CONFIG',str(Path(__file__).resolve().parents[3]/'.runtime/benign-lab/workstation.json')))
 if not p.exists():return {}
 return json.loads(p.read_text())
def request(path,payload=None):
 c=config();body=None if payload is None else json.dumps(payload).encode()
 req=urllib.request.Request(c['url']+path,data=body,headers={'Authorization':'Bearer '+c['token'],'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=50 if payload else 18) as r:return json.load(r)
def states():
 c=config()
 if not c:return {}
 try:
  result=request('/states');return {n:result.get(n,'unknown') for n in c['vms']}
 except Exception:return {n:'unknown' for n in c['vms']}
def owns(name):return name in config().get('vms',[])
def power(name,action):
 try:return bool(request('/power',{'name':name,'action':action}).get('ok'))
 except Exception:return False
