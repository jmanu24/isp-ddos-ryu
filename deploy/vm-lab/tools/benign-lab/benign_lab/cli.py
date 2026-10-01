import argparse
import json
import os
from pathlib import Path
from .config import ROOT,load_lab,mapping_issues,resolve
from .planner import generate,load_profiles,save_plan,validate


def main():
    p=argparse.ArgumentParser(description='BENIGN Lab: reproducible traffic experiments')
    sub=p.add_subparsers(dest='command',required=True)
    s=sub.add_parser('serve')
    s.add_argument('--host',default='127.0.0.1')
    s.add_argument('--port',type=int,default=8765)
    s.add_argument('--lab',default=str(ROOT/'config/lab.demo.yaml'))
    s.add_argument('--data',default=str(ROOT/'data'))
    s.add_argument('--profiles',default=str(ROOT/'profiles'))
    g=sub.add_parser('generate-plan')
    g.add_argument('--seed',type=int,default=1)
    g.add_argument('--duration',type=float,default=600)
    g.add_argument('--lab',default=str(ROOT/'config/lab.demo.yaml'))
    g.add_argument('--profiles',default=str(ROOT/'profiles'))
    g.add_argument('--out',default='benign_plan.json')
    v=sub.add_parser('validate-plan')
    v.add_argument('path')
    m=sub.add_parser('inspect-mapping')
    m.add_argument('--lab',default=str(ROOT/'config/lab.real.yaml'))
    m.add_argument('--plan')
    args=p.parse_args()
    if args.command=='serve':
        if args.host not in ('127.0.0.1','localhost','::1') and not os.getenv('BENIGN_API_TOKEN'):
            p.error('Set BENIGN_API_TOKEN before binding a network interface')
        import uvicorn
        from .api import create_app
        uvicorn.run(create_app(args.data,args.lab,args.profiles),host=args.host,port=args.port,workers=1)
    elif args.command=='generate-plan':
        plan=generate(load_profiles(args.profiles),args.seed,args.duration,load_lab(args.lab)['capacity_mbps'])
        save_plan(plan,args.out)
        print(json.dumps(dict(path=str(Path(args.out).resolve()),plan_hash=plan['plan_hash'],summary=plan['summary'],warnings=plan['warnings']),indent=2))
    elif args.command=='inspect-mapping':
        cfg=load_lab(args.lab)
        issues=mapping_issues(cfg)
        result=dict(scope='configuration_only',ok=not issues,missing_parameters=issues)
        if args.plan and not issues:
            plan=validate(json.loads(Path(args.plan).read_text()))
            result['groups']=[dict(command=g['argv'],context=g['context'],sources=sorted(g['sources'])) for g in resolve(cfg,plan).values()]
        print(json.dumps(result,indent=2))
        if issues: raise SystemExit(2)
    else:
        plan=validate(json.loads(Path(args.path).read_text()))
        print('Verified SHA-256:',plan['plan_hash'])

if __name__=='__main__': main()
