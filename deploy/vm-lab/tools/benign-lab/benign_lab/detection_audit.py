"""One persistent authenticated SSH stream; loss of evidence stays explicit."""
import asyncio,json,os,sqlite3,threading,time,uuid
from pathlib import Path

class DetectionAuditMonitor:
    def __init__(self,root,cfg):
        self.cfg=cfg;self.control=cfg.get('baseline_control',{});self.options=cfg.get('detection_audit',{});self.enabled=self.options.get('enabled',False)
        self.db=sqlite3.connect(str(Path(root)/'detection_audit.sqlite'),check_same_thread=False);self.lock=threading.RLock()
        self.db.execute('CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT,ts REAL,event_id TEXT UNIQUE,body TEXT)');self.db.execute('CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts)');self.db.commit();self.task=None;self.status={'enabled':self.enabled,'status':'disabled' if not self.enabled else 'connecting'}
    def accept(self,message):
        if message.get('error'):
            message=dict(message,events=list(message.get('events',[]))+[dict(schema=1,event_id=uuid.uuid4().hex,kind='capture_gap',timestamp=message.get('timestamp',time.time()),gap_start=message.get('timestamp',time.time())-5,gap_end=message.get('timestamp',time.time()),reason=message['error'])])
        with self.lock:
            for row in message.get('events',[]):
                if row.get('schema')!=1 or not isinstance(row.get('timestamp'),(int,float)):continue
                self.db.execute('INSERT OR IGNORE INTO audit(ts,event_id,body) VALUES(?,?,?)',(row['timestamp'],row.get('event_id'),json.dumps(row)))
            self.db.execute('DELETE FROM audit WHERE ts<?',(time.time()-21600,));self.db.commit()
        self.status=dict(enabled=True,status='connected' if not message.get('error') else 'error',received_at=time.time(),error=message.get('error'))
    def rows(self,start,end,after=0):
        with self.lock:records=self.db.execute('SELECT id,body FROM audit WHERE ts>=? AND ts<=? AND id>? ORDER BY id',(start,end,after)).fetchall()
        return [dict(json.loads(body),id=key) for key,body in records]
    async def collect(self):
        while True:
            proc=None;drain=None
            try:
                env=os.environ.copy();secret=env.get(self.control.get('password_env','BENIGN_SSH_PASSWORD'))
                if not secret:raise RuntimeError('Audit SSH credential unavailable')
                env['SSHPASS']=secret
                argv=['sshpass','-e','ssh','-T','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','-o','UserKnownHostsFile='+self.control['known_hosts_file'],self.control['user']+'@'+self.control['host'],'sudo -n python3 -u -']
                proc=await asyncio.create_subprocess_exec(*argv,stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env=env,limit=4*1024*1024)
                code=(Path(__file__).with_name('audit_probe.py')).read_text();proc.stdin.write(code.encode());await proc.stdin.drain();proc.stdin.close()
                async def discard():
                    while await proc.stderr.read(4096):pass
                drain=asyncio.create_task(discard())
                while True:
                    line=await asyncio.wait_for(proc.stdout.readline(),20)
                    if not line:raise RuntimeError('Audit stream disconnected')
                    self.accept(json.loads(line))
            except asyncio.CancelledError:raise
            except Exception as exc:
                self.accept(dict(timestamp=time.time(),events=[],error=str(exc)));self.status.update(status='disconnected')
            finally:
                if drain:drain.cancel();await asyncio.gather(drain,return_exceptions=True)
                if proc and proc.returncode is None:
                    proc.terminate()
                    try:await asyncio.wait_for(proc.wait(),3)
                    except asyncio.TimeoutError:proc.kill();await proc.wait()
            await asyncio.sleep(5)
    def start(self):
        if self.enabled:self.task=asyncio.create_task(self.collect())
    async def stop(self):
        if self.task:self.task.cancel();await asyncio.gather(self.task,return_exceptions=True)
        self.db.close()
