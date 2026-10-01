"""Integration verification of both receive-accounting directions."""
import json
from pathlib import Path
import subprocess
import sys
import time
def test_delivered_accounting():
    probe=Path(__file__).with_name('capacity_probe.py')
    server=subprocess.Popen([sys.executable,str(probe),'server','--target','127.0.0.1','--port','19091'])
    try:
        time.sleep(.3)
        for direction in ('ul','dl'):
            result=subprocess.run([sys.executable,str(probe),'client','--source','127.0.0.1','--target','127.0.0.1','--port','19091','--direction',direction,'--duration','3','--streams','2'],capture_output=True,text=True,timeout=15,check=True)
            data=json.loads(result.stdout)
            assert len(data['streams'])==2 and data['mbps']>0
            assert all(row['bytes']>0 and row['seconds']==1 for row in data['streams'])
            print(direction+': two streams, delivered bytes and warmup exclusion verified')
    finally:
        server.terminate()
        server.wait(timeout=5)

if __name__=='__main__':
    test_delivered_accounting()
