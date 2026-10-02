"""Standalone, read-only Linux interface sampler (Python 3.8+)."""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

FIELDS=('rx_bytes','tx_bytes','rx_packets','tx_packets','rx_dropped','tx_dropped','rx_errors','tx_errors')


def read_interfaces(root=Path('/sys/class/net')):
    result=[]
    for iface in sorted(root.iterdir()):
        if iface.name=='lo' or iface.name.startswith(('veth','docker','virbr')):continue
        try:
            values={field:int((iface/'statistics'/field).read_text()) for field in FIELDS}
            result.append(dict(interface=iface.name,operstate=(iface/'operstate').read_text().strip(),**values))
        except (OSError,ValueError):continue
    return result


def rates(before,current,elapsed):
    if before is None or elapsed<=0 or any(current[k]<before[k] for k in ('rx_bytes','tx_bytes')):
        return dict(rx_mbps=None,tx_mbps=None,counter_reset=before is not None)
    return dict(rx_mbps=(current['rx_bytes']-before['rx_bytes'])*8/elapsed/1e6,
                tx_mbps=(current['tx_bytes']-before['tx_bytes'])*8/elapsed/1e6,counter_reset=False)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--once',action='store_true')
    parser.add_argument('--namespaces',default='')
    parser.add_argument('--interval',type=float,default=5)
    args=parser.parse_args()
    if args.once:
        print(json.dumps(read_interfaces()),flush=True);return
    namespaces=[x for x in args.namespaces.split(',') if x]
    if any(not re.fullmatch(r'(?:ue[1-5]|fixed(?:[1-9]|10))',x) for x in namespaces):raise ValueError('Invalid subscriber namespace')
    previous={}
    while True:
        begin=time.monotonic()
        items=[dict(namespace='',**row) for row in read_interfaces()]
        errors={}
        for namespace in namespaces:
            try:
                proc=subprocess.run(['ip','netns','exec',namespace,sys.executable,__file__,'--once'],capture_output=True,text=True,timeout=3)
                if proc.returncode:raise RuntimeError('Namespace counters unavailable')
                items.extend(dict(namespace=namespace,**row) for row in json.loads(proc.stdout))
            except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:errors[namespace]=str(exc)
        now=time.monotonic()
        for row in items:
            key=(row['namespace'],row['interface'])
            before=previous.get(key)
            row.update(rates(before[1] if before else None,row,now-before[0] if before else 0))
            previous[key]=(now,dict(row))
        present={(r['namespace'],r['interface']) for r in items}
        previous={k:v for k,v in previous.items() if k in present}
        print(json.dumps(dict(timestamp=time.time(),items=items,errors=errors)),flush=True)
        time.sleep(max(.1,args.interval-(time.monotonic()-begin)))

if __name__=='__main__':
    try:main()
    except (KeyboardInterrupt,BrokenPipeError):pass
