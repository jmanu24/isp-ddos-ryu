"""Password-authenticated SSH without secrets in argv or worker protocol."""
import argparse
import json
import os
import sys


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--password-env',default='BENIGN_SSH_PASSWORD')
    p.add_argument('--credentials')
    p.add_argument('command',nargs=argparse.REMAINDER)
    args=p.parse_args()
    command=args.command
    if command and command[0]=='--': command=command[1:]
    password=os.environ.get(args.password_env)
    if args.credentials:
        with open(args.credentials) as f: password=json.load(f)['password']
    if not password: raise SystemExit('SSH credential missing; set password environment variable')
    env=os.environ.copy()
    env['SSHPASS']=password
    # BatchMode=yes disables password authentication; replace the executor default.
    command=['BatchMode=no' if item=='BatchMode=yes' else item for item in command]
    os.execvpe('sshpass',['sshpass','-e',*command],env)


if __name__=='__main__': main()
