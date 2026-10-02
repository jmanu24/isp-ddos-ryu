"""Read-only Linux VM/process resource counters, compatible with Python 3.6+."""
import os,time
from pathlib import Path

def snapshot(root=Path('/proc')):
    cpu=list(map(int,next(l for l in (root/'stat').read_text().splitlines() if l.startswith('cpu ')).split()[1:]))[:8]
    mem={l.split(':')[0]:int(l.split()[1])*1024 for l in (root/'meminfo').read_text().splitlines()}
    namespaces={}
    try:
        for p in Path('/var/run/netns').iterdir():namespaces[p.stat().st_ino]=p.name
    except OSError:pass
    processes={}
    for p in root.iterdir():
        if not p.name.isdigit():continue
        try:
            text=(p/'stat').read_text();rest=text[text.rindex(')')+2:].split();identity=(int(p.name),int(rest[19]));io={}
            try:io={l.split(':')[0]:int(l.split()[1]) for l in (p/'io').read_text().splitlines()}
            except OSError:pass
            try:namespace=namespaces.get((p/'ns/net').stat().st_ino,'')
            except OSError:namespace=''
            processes[identity]=dict(pid=int(p.name),start_ticks=int(rest[19]),ppid=int(rest[1]),name=text[text.index('(')+1:text.rindex(')')],ticks=int(rest[11])+int(rest[12]),rss_bytes=int(rest[21])*os.sysconf('SC_PAGE_SIZE'),read_bytes=io.get('read_bytes'),write_bytes=io.get('write_bytes'),namespace=namespace)
        except (OSError,ValueError,IndexError,UnicodeError):pass
    disks={}
    try:
        whole={p.name for p in Path('/sys/block').iterdir() if not p.name.startswith(('loop','ram','sr','fd'))}
        for l in (root/'diskstats').read_text().splitlines():
            a=l.split()
            if len(a)>=14 and a[2] in whole:disks[a[2]]=dict(read_bytes=int(a[5])*512,write_bytes=int(a[9])*512,io_ms=int(a[12]),reads=int(a[3]),writes=int(a[7]))
    except OSError:pass
    return dict(timestamp=time.time(),mono=time.monotonic(),cpu=cpu,memory=mem,processes=processes,disks=disks,load=list(os.getloadavg()),logical_cpus=os.cpu_count() or 1)

def difference(old,new):
    elapsed=new['mono']-old['mono']
    if elapsed<=0:raise ValueError('Non-positive sampling interval')
    delta=[b-a for a,b in zip(old['cpu'],new['cpu'])];total=sum(delta);valid=total>0 and min(delta)>=0
    mem=new['memory'];available=mem.get('MemAvailable',mem.get('MemFree',0)+mem.get('Buffers',0)+mem.get('Cached',0))
    row=dict(timestamp=new['timestamp'],interval_s=elapsed,platform='linux_guest',metrics_kind='guest_resources',logical_cpus=new['logical_cpus'],cpu_pct=100*(total-delta[3]-delta[4])/total if valid else None,iowait_pct=100*delta[4]/total if valid else None,steal_pct=100*delta[7]/total if valid else None,memory_total_bytes=mem['MemTotal'],memory_available_bytes=available,memory_pct=100*(1-available/mem['MemTotal']),load=new['load'],processes=[],disks=[])
    for identity,p in new['processes'].items():
        a=old['processes'].get(identity)
        if not a:continue
        ticks=p['ticks']-a['ticks']
        if ticks<0:continue
        x=dict(p,cpu_pct=100*ticks/os.sysconf('SC_CLK_TCK')/elapsed);x.pop('ticks')
        for field in ['read_bytes','write_bytes']:
            x[field+'_per_s']=(p[field]-a[field])/elapsed if p[field] is not None and a[field] is not None and p[field]>=a[field] else None
        row['processes'].append(x)
    top=sorted(row['processes'],key=lambda p:p['cpu_pct'],reverse=True)[:15]+sorted(row['processes'],key=lambda p:p['rss_bytes'],reverse=True)[:8]
    row['processes']=list({(p['pid'],p['start_ticks']):p for p in top}.values())
    for name,b in new['disks'].items():
        a=old['disks'].get(name)
        if not a or any(b[k]<a[k] for k in b):continue
        row['disks'].append(dict(device=name,read_bytes_per_s=(b['read_bytes']-a['read_bytes'])/elapsed,write_bytes_per_s=(b['write_bytes']-a['write_bytes'])/elapsed,busy_pct=min(100,100*(b['io_ms']-a['io_ms'])/(elapsed*1000)),read_iops=(b['reads']-a['reads'])/elapsed,write_iops=(b['writes']-a['writes'])/elapsed))
    return row
