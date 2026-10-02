import subprocess,time,socket,json,os,signal,sys
from pathlib import Path
import pytest

@pytest.mark.skipif(sys.platform != "linux", reason="Linux SO_REUSEPORT and /proc")
def test_parallel_receiver_protocols_and_failure_cleanup():
    p=subprocess.Popen([sys.executable,str(Path(__file__).resolve().parents[1]/'benign_lab/agent.py'),'receiver','--host','127.0.0.1','--tcp-port','19001','--udp-port','19002','--http-port','19003','--workers','4'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
     for _ in range(4):
      line=p.stdout.readline();assert 'Receiver ready:' in line,line
     children=[int(x) for x in open('/proc/%s/task/%s/children'%(p.pid,p.pid)).read().split()]
     assert len(children)==5,children # four workers plus multiprocessing resource tracker
     for _ in range(40):
      with socket.create_connection(('127.0.0.1',19001),2) as s:
       s.sendall((json.dumps(dict(direction='dl',bytes=2400,rate_bps=10000000,duration_s=2))+'\n').encode());data=b''
       while True:
        b=s.recv(4096)
        if not b:break
        data+=b
       assert len(data)==2400,len(data)
     with socket.create_connection(('127.0.0.1',19003),2) as s:
      s.sendall(b'GET /?n=1200 HTTP/1.1\r\nHost: localhost\r\n\r\n');data=b''
      while True:
       b=s.recv(4096)
       if not b:break
       data+=b
      assert b'200 OK' in data and len(data.split(b'\r\n\r\n',1)[1])==1200
     s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b'BLDL:800',('127.0.0.1',19002));assert len(s.recv(2000))==800;s.close()
     os.kill(children[-1],signal.SIGTERM);assert p.wait(timeout=10)!=0
     # The resource tracker exits asynchronously on pipe EOF after its parent.
     cleanup_deadline=time.monotonic()+3
     while any(os.path.exists('/proc/'+str(pid)) for pid in children) and time.monotonic()<cleanup_deadline:
      time.sleep(.02)
     assert not any(os.path.exists('/proc/'+str(pid)) for pid in children),'Orphan worker'
     print('PASS: four workers, 40 TCP transfers, HTTP, UDP, worker failure and cleanup')
    finally:
     if p.poll() is None:p.terminate();p.wait(timeout=10)
