"""Loopback-only VMware Player control endpoint, reached through SSH reverse forwarding."""
import argparse,json,hmac,subprocess
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
p=argparse.ArgumentParser();p.add_argument('--config',required=True);args=p.parse_args()
cfg=json.loads(Path(args.config).read_text());token=cfg['token'];vms=cfg['vms'];vmrun=cfg['vmrun']
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def authorized(self):return hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+token)
 def respond(self,status,data):
  body=json.dumps(data).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def do_GET(self):
  if not self.authorized():return self.respond(401,{'error':'unauthorized'})
  if self.path!='/states':return self.respond(404,{'error':'not found'})
  try:
   r=subprocess.run([vmrun,'-T','player','list'],capture_output=True,text=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
   if r.returncode:raise RuntimeError('vmrun failed')
   running={str(Path(x).resolve()).lower() for x in r.stdout.splitlines()[1:] if x.strip()}
   return self.respond(200,{k:'poweredOn' if str(Path(v).resolve()).lower() in running else 'poweredOff' for k,v in vms.items()})
  except Exception:return self.respond(503,{'error':'workstation unavailable'})
 def do_POST(self):
  if not self.authorized():return self.respond(401,{'error':'unauthorized'})
  if self.path!='/power':return self.respond(404,{'error':'not found'})
  try:
   n=int(self.headers.get('Content-Length','0'))
   if n<1 or n>2048:return self.respond(400,{'error':'invalid request'})
   data=json.loads(self.rfile.read(n));name=data['name'];action=data['action'];path=vms[name]
   assert action in ['on','off','shutdown']
   command=['start',path,'nogui'] if action=='on' else ['stop',path,'soft' if action=='shutdown' else 'hard']
   r=subprocess.run([vmrun,'-T','player',*command],capture_output=True,text=True,timeout=45,creationflags=subprocess.CREATE_NO_WINDOW)
   self.respond(200 if r.returncode==0 else 503,{'ok':r.returncode==0})
  except Exception:self.respond(400,{'error':'operation failed'})
ThreadingHTTPServer(('127.0.0.1',18781),Handler).serve_forever()
