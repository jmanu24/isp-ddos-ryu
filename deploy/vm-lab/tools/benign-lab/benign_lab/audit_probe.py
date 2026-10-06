"""Read-only tail of structured controller evidence, Python 3.8+."""
import json,os,sys,time
from pathlib import Path
path=Path(sys.argv[1] if len(sys.argv)>1 else '/var/log/ryu-manager.log')
offset=path.stat().st_size if path.exists() else 0;inode=None
while True:
    events=[];error=None
    try:
        stat=path.stat()
        if inode is not None and (inode!=stat.st_ino or stat.st_size<offset):offset=0
        inode=stat.st_ino
        with path.open('rb') as stream:
            stream.seek(offset);chunk=stream.read(2*1024*1024)
            if chunk and not chunk.endswith(b'\n'):chunk=chunk[:chunk.rfind(b'\n')+1]
            offset+=len(chunk)
        for line in chunk.splitlines():
            if b'LAB_AUDIT_WRITE_FAILED' in line:error='Controller audit record could not be serialized'
            marker=line.find(b'LAB_AUDIT ')
            if marker<0:continue
            try:
                row=json.loads(line[marker+10:]);assert row.get('schema')==1
                events.append(row)
            except (ValueError,AssertionError):error='Malformed audit record'
    except OSError as exc:error=str(exc)
    print(json.dumps(dict(timestamp=time.time(),events=events,error=error)),flush=True)
    time.sleep(2)
