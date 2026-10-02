"""Apply the shared-host radio scheduling policy; run on the control node."""
import argparse,json,subprocess
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--latency',choices=['normal','high'],default='high');a=p.parse_args()
    root=Path(__file__).resolve().parents[5];private=root/'.runtime/benign-lab'
    if any(json.loads(f.read_text())['status'] in ('queued','preparing','running') for f in (private/'data/runs').glob('*/run.json')):
        p.error('Stop active experiments before changing scheduling')
    r=subprocess.run(['bash','-c','set -a; source '+str(root/'deploy/vm-lab/.govc.env')+'; env -0'],capture_output=True,check=True)
    env=dict(x.decode().split('=',1) for x in r.stdout.split(b'\0') if b'=' in x)
    for name in ['ue','ue2','du','du2','du3','du4','du5']:
        subprocess.run(['govc','vm.change','-vm',name,'-cpu.shares','normal','-latency',a.latency],env=env,check=True)
        print(name+': shares normal, latency '+a.latency,flush=True)
    audit=private/'cpu-upgrade';audit.mkdir(exist_ok=True)
    r=subprocess.run(['govc','vm.info','-json','*'],env=env,capture_output=True,check=True)
    (audit/('policy-'+a.latency+'.json')).write_bytes(r.stdout)

if __name__=='__main__':main()
