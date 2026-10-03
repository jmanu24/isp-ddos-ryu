"""Install supervisor, pool and agent together using private laboratory inventory."""
import sys,base64,shlex,concurrent.futures,json
from pathlib import Path
repo=Path(__file__).resolve().parents[5];app=Path(__file__).resolve().parents[1];stage=app
active=[]
for path in (repo/'.runtime/benign-lab/data/runs').glob('*/run.json'):
 run=json.loads(path.read_text())
 if run['status'] not in {'completed','completed_with_errors','failed','stopped','interrupted'}:active.append(run['id'])
if active:raise RuntimeError('Stop active experiments before installing agents: '+str(active))
sys.path.insert(0,str(repo/'deploy/vm-lab'))
import webtool.ssh_ops as ssh
from webtool.inventory import credentials_for
orig=ssh._target
def target(n):
 if n=='peer-router':
  u,p=credentials_for(n);return '10.30.0.2',u,p
 return orig(n)
ssh._target=target
files=['connection_pool.py','supervisor.py','agent.py']
def update(n):
 payload={f:base64.b64encode((stage/'benign_lab'/f).read_bytes()).decode() for f in files}
 code="from pathlib import Path; import base64,py_compile,sys; assert sys.version_info >= (3,8), 'Python 3.8+ required'; root=Path('/opt/benign-lab'); root.mkdir(exist_ok=True); payload="+repr(payload)+"; [(root/f).with_suffix('.pre-optimized.py').write_bytes((root/f).read_bytes()) for f in payload if (root/f).exists() and not (root/f).with_suffix('.pre-optimized.py').exists()]; [(root/f).write_bytes(base64.b64decode(v)) for f,v in payload.items()]; [py_compile.compile(str(root/f),doraise=True) for f in payload]; print(sys.version.split()[0])"
 r=ssh.run(n,'python3 -c '+shlex.quote(code),timeout=30,become=True)
 if r.rc:raise RuntimeError(n+': '+r.stderr)
 if n=='victim':
  r=ssh.run(n,'rc-service benign-lab-receiver restart',timeout=30,become=True)
  if r.rc:raise RuntimeError(n+': receiver restart failed '+r.stderr)
 elif n.startswith('ent-site-'):
  result=ssh.run(n,'systemctl restart benign-lab-receiver.service',timeout=30,become=True)
  if result.rc:raise RuntimeError(n+': receiver restart failed '+result.stderr)
 return n,r.stdout.strip()
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
 print(json.dumps({'guests':dict(pool.map(update,['ue','ue2','suscriptor','peer-router']+['ent-site-'+str(i) for i in range(1,6)]+['victim']))}),flush=True)
