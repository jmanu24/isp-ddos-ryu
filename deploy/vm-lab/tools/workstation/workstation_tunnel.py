"""Maintain an authenticated reverse SSH forward without exposing a Windows port."""
import subprocess,time,argparse,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--config',required=True);a=p.parse_args();cfg=json.loads(Path(a.config).read_text())
while True:
 subprocess.run(['ssh','-NT','-i',cfg['ssh_key'],'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3','-R','127.0.0.1:18781:127.0.0.1:18781','ubuntu@192.168.18.154'],creationflags=subprocess.CREATE_NO_WINDOW)
 time.sleep(5)
