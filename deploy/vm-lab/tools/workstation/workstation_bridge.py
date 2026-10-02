"""Loopback-only VMware Player control endpoint, reached through SSH reverse forwarding."""
import argparse,json,hmac,subprocess,ctypes,threading,time,os
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
p=argparse.ArgumentParser();p.add_argument('--config',required=True);args=p.parse_args()
cfg=json.loads(Path(args.config).read_text());token=cfg['token'];vms=cfg['vms'];vmrun=cfg['vmrun']

_cpu_lock=threading.Lock();_cpu_sample=None
class FileTime(ctypes.Structure):
 _fields_=[('low',ctypes.c_ulong),('high',ctypes.c_ulong)]
def cpu_times():
 idle,kernel,user=FileTime(),FileTime(),FileTime()
 if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle),ctypes.byref(kernel),ctypes.byref(user)):raise OSError('CPU counters unavailable')
 value=lambda v:(v.high<<32)|v.low
 return value(idle),value(kernel)+value(user)
def collect_cpu():
 global _cpu_sample
 old=cpu_times();before=time.monotonic()
 while True:
  time.sleep(5)
  try:
   current=cpu_times();now=time.monotonic();total=current[1]-old[1];idle=current[0]-old[0]
   if total>0:
    row=dict(platform='windows',timestamp=time.time(),interval_s=now-before,cpu_pct=max(0,min(100,100*(total-idle)/total)),logical_cpus=os.cpu_count(),metrics_kind='host_cpu')
    with _cpu_lock:_cpu_sample=row
   old=current;before=now
  except OSError:pass
threading.Thread(target=collect_cpu,daemon=True).start()

class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def authorized(self):return hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+token)
 def respond(self,status,data):
  body=json.dumps(data).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def do_GET(self):
  if not self.authorized():return self.respond(401,{'error':'unauthorized'})
  if self.path=='/resources':
   with _cpu_lock:row=_cpu_sample
   return self.respond(200,row) if row and time.time()-row['timestamp']<20 else self.respond(503,{'error':'CPU sample unavailable'})
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
