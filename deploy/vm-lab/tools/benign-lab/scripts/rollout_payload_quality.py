import json,sys,base64,shlex,hashlib,concurrent.futures
from pathlib import Path
root=Path('/home/ubuntu/isp-ddos-ryu');private=root/'.runtime/benign-lab';sys.path.insert(0,str(root/'deploy/vm-lab'));from webtool import ssh_ops
terminal={'completed','completed_with_errors','failed','stopped','interrupted'}
for p in (private/'data/runs').glob('*/run.json'):assert json.loads(p.read_text())['status'] in terminal,'Active run'
assert all(j['status'] in {'completed','failed','cancelled','attention'} for j in json.loads((private/'data/experiment_jobs.json').read_text()).values()),'Active job'
source=(root/'deploy/vm-lab/tools/benign-lab/benign_lab/agent.py').read_bytes();digest=hashlib.sha256(source).hexdigest();encoded=base64.b64encode(source).decode()
def deploy(name):
 code="from pathlib import Path;import base64,hashlib,os,stat;data=base64.b64decode("+repr(encoded)+");p=Path('/opt/benign-lab/agent.py');assert p.resolve().parent==Path('/opt/benign-lab').resolve();compile(data,str(p),'exec');old=p.stat();backup=p.with_suffix('.py.pre-quota-v2');backup.write_bytes(p.read_bytes()) if not backup.exists() else None;t=p.with_suffix('.py.quota-v2.tmp');t.write_bytes(data);os.chmod(t,stat.S_IMODE(old.st_mode));os.chown(t,old.st_uid,old.st_gid);t.replace(p);print(hashlib.sha256(p.read_bytes()).hexdigest())"
 r=ssh_ops.run(name,'python3 -c '+shlex.quote(code),timeout=25,become=True);assert r.rc==0,(name,r.stderr[-400:]);assert r.stdout.strip()==digest,(name,r.stdout[-200:]);print(name+' verified',flush=True);return name,digest
names=['ue','ue2','suscriptor']+['ent-site-'+str(i) for i in range(1,6)]+['peer-router']
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:results=dict(pool.map(deploy,names))
(private/'quota-stage/worker-attestation.json').write_text(json.dumps(results,indent=2));print('All nine worker VMs verified; no service restarted')
