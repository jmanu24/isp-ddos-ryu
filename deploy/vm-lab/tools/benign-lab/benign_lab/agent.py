"""Dependency-free worker and bounded TCP/UDP/HTTP receiver, Python >=3.8.

stdin: prepare JSON, then {start_unix: ...}; EOF or STOP cancels every task.
stdout: newline-delimited JSON. Keep stdout free of human diagnostics.
"""
from __future__ import annotations
import argparse
import asyncio
from asyncio import TimeoutError
import json
import math
import multiprocessing
import os
import shutil
import signal
import socket
import sys
import time
from urllib.parse import urlparse, parse_qs

MAX_BYTES = 100_000_000_000


class AsyncTimeout:
    """Deadline context for Python 3.8+; preserve external cancellation."""
    def __init__(self, delay=None, deadline=None):
        self.delay,self.deadline=delay,deadline
        self.expired=False
    async def __aenter__(self):
        loop=asyncio.get_running_loop()
        self.task=asyncio.current_task()
        deadline=self.deadline if self.deadline is not None else loop.time()+self.delay
        def expire():
            self.expired=True
            self.task.cancel()
        self.handle=loop.call_at(deadline,expire)
        return self
    async def __aexit__(self, kind, value, traceback):
        self.handle.cancel()
        if kind is asyncio.CancelledError and self.expired:
            if hasattr(self.task,'uncancel'): self.task.uncancel()
            raise TimeoutError() from value
        return False


def emit(value):
    print(json.dumps(value, separators=(',', ':')), flush=True)


async def paced_send(writer, size, rate, packet, deadline, on_chunk=None):
    started, sent = time.monotonic(), 0
    while sent < size and time.monotonic() < deadline:
        wait = started + sent * 8 / max(rate, 1) - time.monotonic()
        if wait > 0:
            await asyncio.sleep(min(wait, max(0, deadline-time.monotonic())))
        if time.monotonic() >= deadline:
            break
        chunk = b'x' * min(packet, size-sent)
        writer.write(chunk)
        await writer.drain()
        sent += len(chunk)
        if on_chunk:
            on_chunk(len(chunk))
    return sent


async def receive_client(reader, writer):
    try:
        line = await asyncio.wait_for(reader.readline(), 3)
        is_http = line.startswith((b'GET ', b'POST '))
        if is_http:
            method, target, _ = line.decode().split()
            headers = {}
            while True:
                raw = await asyncio.wait_for(reader.readline(), 3)
                if raw in (b'\r\n', b'\n', b''): break
                k,v = raw.decode().split(':', 1)
                headers[k.lower()] = v.strip()
            query = parse_qs(urlparse(target).query)
            cfg = dict(direction='dl' if method == 'GET' else 'ul', bytes=int(query.get('n', [headers.get('content-length', 0)])[0]),
                       rate_bps=float(query.get('rate', [1e6])[0]), duration_s=float(query.get('duration', [30])[0]), packet=1200)
        else:
            cfg = json.loads(line)
        size, rate, duration = int(cfg['bytes']), float(cfg['rate_bps']), float(cfg['duration_s'])
        if not (0 <= size <= MAX_BYTES and 0 < rate <= 1e11 and 0 < duration <= 3600):
            raise ValueError('Transfer limits exceeded')
        deadline = time.monotonic() + duration
        async with AsyncTimeout(duration + 2):
            if cfg['direction'] == 'dl':
                if is_http:
                    writer.write(f'HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n'.encode())
                await paced_send(writer, size, rate, min(1400,max(28,int(cfg.get('packet',1200)))), deadline)
            else:
                got = 0
                while got < size:
                    data = await reader.read(min(65536, size-got))
                    if not data: break
                    got += len(data)
                if is_http:
                    writer.write(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    await writer.drain()
    except (ValueError, KeyError, ConnectionError, TimeoutError, OSError):
        pass
    finally:
        writer.close()
        try: await writer.wait_closed()
        except (OSError, ConnectionError): pass


class UDPReceiver(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, addr):
        if data.startswith(b'BLDL:'):
            try:
                n = int(data[5:])
                if 1 <= n <= 1400:
                    self.transport.sendto(b'x'*n, addr)
            except ValueError:
                pass


async def receiver(host, tcp, udp, http, reuse_port=False):
    servers = [await asyncio.start_server(receive_client, host, port, reuse_port=reuse_port) for port in (tcp,http)]
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(UDPReceiver, local_addr=(host,udp), reuse_port=reuse_port)
    print(f'Receiver ready: pid={os.getpid()} {host} TCP={tcp}, UDP={udp}, HTTP={http}', flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()
        for s in servers:
            s.close()
            await s.wait_closed()


async def traffic(e, target, metrics, deadline, context=None):
    context=context or {}
    source=context.get('source_ip')
    interface=context.get('interface')
    metrics['source_ip']=source
    metrics['source_interface']=interface
    size, rate, packet = e['planned_bytes'], e['rate_bps'], e['packet_size_bytes']
    proto, direction = e['wire_protocol'], e['direction']
    def add(kind, n):
        metrics[f'bytes_{kind}'] += n
        metrics[f'chunks_{kind}'] += 1
    if proto in ('tcp','http'):
        port = target['http_port' if proto == 'http' else 'tcp_port']
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target['host'], port,local_addr=(source,0) if source else None), 3)
        metrics['source_ip'],metrics['src_port'] = writer.get_extra_info('sockname')[:2]
        metrics['dst_port'] = port
        try:
            remaining = max(.001, deadline-time.monotonic())
            if proto == 'http':
                path = f'/bytes?n={size}&rate={rate}&duration={remaining}'
                request = f'{"GET" if direction == "dl" else "POST"} {path} HTTP/1.1\r\nHost: {target["host"]}\r\nContent-Length: {0 if direction == "dl" else size}\r\nConnection: close\r\n\r\n'
                writer.write(request.encode())
            else:
                writer.write((json.dumps(dict(direction=direction, bytes=size, rate_bps=rate, duration_s=remaining, packet=packet))+'\n').encode())
            await writer.drain()
            if direction == 'ul':
                await paced_send(writer, size, rate, packet, deadline, lambda n:add('tx',n))
            else:
                if proto == 'http':
                    status = await reader.readline()
                    if b' 200 ' not in status:
                        raise ValueError('HTTP receiver returned non-200')
                    while await reader.readline() not in (b'\r\n', b'\n', b''):
                        pass
                while metrics['bytes_rx'] < size:
                    data = await reader.read(min(65536,size-metrics['bytes_rx']))
                    if not data: break
                    add('rx',len(data))
                if metrics['bytes_rx'] < size and time.monotonic() < deadline-.1:
                    raise ConnectionError('Receiver closed before completing payload')
        finally:
            writer.close()
            try: await writer.wait_closed()
            except OSError: pass
    elif proto == 'udp':
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(target['host'], target['udp_port'], family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        if source: sock.bind((source,0))
        sock.connect(infos[0][4])
        metrics['source_ip'],metrics['src_port'] = sock.getsockname()[:2]
        metrics['dst_port'] = target['udp_port']
        start, sent = time.monotonic(), 0
        try:
            while sent < size and time.monotonic() < deadline:
                wait = start + sent*8/max(rate,1)-time.monotonic()
                if wait > 0: await asyncio.sleep(min(wait,max(0,deadline-time.monotonic())))
                if time.monotonic() >= deadline: break
                n = min(packet,size-sent)
                if direction == 'ul':
                    await loop.sock_sendall(sock,b'x'*n)
                    add('tx',n)
                else:
                    await loop.sock_sendall(sock,f'BLDL:{n}'.encode())
                    data = await asyncio.wait_for(loop.sock_recv(sock,1400),min(1,max(.001,deadline-time.monotonic())))
                    add('rx',len(data))
                sent += n
        finally:
            sock.close()
    elif proto == 'icmp':
        # Ping observations are kept separate from TCP application chunk counts.
        interval = max(.02, packet*8/max(rate,1))
        count = max(1, math.ceil(size/packet))
        args = ['ping','-n','-c',str(count),'-i',str(interval),'-s',str(packet),target['host']]
        if source: args[1:1]=['-I',source]
        proc = await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        try:
            while True:
                line = await proc.stdout.readline()
                if not line: break
                if b'bytes from' in line:
                    add('rx',packet)
                    metrics['icmp_replies'] += 1
            await proc.wait()
            if proc.returncode:
                raise RuntimeError((await proc.stderr.read()).decode()[:500] or 'ping failed')
        finally:
            if proc.returncode is None:
                proc.terminate()
                try: await asyncio.wait_for(proc.wait(),1)
                except TimeoutError:
                    proc.kill()
                    await proc.wait()


async def ip_json(*args):
    proc=await asyncio.create_subprocess_exec('ip','-j',*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
    try:
        out,err=await asyncio.wait_for(proc.communicate(),5)
    except BaseException:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        raise
    if proc.returncode: raise ValueError(err.decode(errors='replace')[:1000])
    return json.loads(out)


async def inspect_context(context, targets, events):
    if not context.get('check_route'): return {'route_checked':False}
    interface=context.get('interface')
    source=context.get('source_ip')
    if not interface or not source: raise ValueError('Route preflight requires interface and source_ip')
    addresses=await ip_json('address','show','dev',interface)
    if not any(a.get('local')==source for link in addresses for a in link.get('addr_info',[])):
        raise ValueError(f'Source IP {source} not assigned to {interface} in execution context')
    routes=[]
    for destination in sorted({e['destination'] for e in events}):
        # Do not force oif here: verify the route the bound socket will actually choose.
        rows=await ip_json('route','get',targets[destination]['host'],'from',source)
        if not rows or rows[0].get('dev')!=interface:
            raise ValueError(f'Unexpected data-plane interface for {destination}: {rows}')
        route=rows[0]
        if context.get('expected_gateway') and route.get('gateway')!=context['expected_gateway']:
            raise ValueError(f'Unexpected gateway for {destination}: {route}')
        routes.append(dict(destination=destination,**route))
    return dict(route_checked=True,source_ip=source,interface=interface,routes=routes,
                session_id=context.get('session_id'),session_validation='operator_mapping_only',
                interfaces=addresses)


async def worker():
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=32*1024*1024)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda:protocol, sys.stdin)
    cfg = json.loads(await reader.readline())
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    if any(e['wire_protocol']=='icmp' for e in cfg['events']) and not shutil.which('ping'):
        emit(dict(type='fatal',error='ping not found'))
        return
    context=cfg.get('context',{})
    evidence={}
    # Connectivity checks happen before the shared start time is selected.
    endpoints = {(cfg['targets'][e['destination']]['host'], cfg['targets'][e['destination']]['http_port' if e['wire_protocol']=='http' else 'tcp_port'])
                 for e in cfg['events'] if e['wire_protocol'] in ('tcp','http')}
    try:
        evidence=await inspect_context(context,cfg['targets'],cfg['events'])
        for host,port in endpoints:
            for attempt in range(3):
                try:
                    _, w = await asyncio.wait_for(asyncio.open_connection(host,port,local_addr=(context['source_ip'],0) if context.get('source_ip') else None),3)
                    w.close()
                    await w.wait_closed()
                    break
                except (OSError, TimeoutError) as exc:
                    if attempt==2:
                        raise ValueError('Cannot connect to %s:%s from %s: %s %s' % (host,port,context.get('source_ip'),type(exc).__name__,exc)) from exc
                    await asyncio.sleep(.2)
    except (OSError, TimeoutError, ValueError) as exc:
        emit(dict(type='fatal',error=f'Receiver preflight: {exc}'))
        return
    emit(dict(type='ready', unix=time.time(),evidence=evidence))
    while True:
        raw = await reader.readline()
        received = time.time()
        if not raw: return
        message = json.loads(raw)
        if message.get('type') == 'clock':
            emit(dict(type='clock',nonce=message['nonce'],received_unix=received,sent_unix=time.time()))
            continue
        if 'start_unix' not in message: return
        start = message['start_unix']
        break
    origin = loop.time() + start-time.time()
    active = {}
    async def control():
        await reader.readline()
        stop.set()
    async def reporter():
        while True:
            await asyncio.sleep(1)
            for eid,metrics in list(active.items()):
                emit(dict(type='metrics',event_id=eid,**metrics))
    async def event(e):
        metrics = dict(bytes_tx=0,bytes_rx=0,chunks_tx=0,chunks_rx=0,icmp_replies=0,src_port=None,dst_port=None)
        started = False
        status, error = 'completed', None
        try:
            await asyncio.sleep(max(0,origin+e['start_s']-loop.time()))
            started = True
            elapsed = loop.time()-origin
            active[e['event_id']] = metrics
            emit(dict(type='event',event_id=e['event_id'],status='running',actual_start_s=elapsed,start_timestamp=time.time(),lateness_s=elapsed-e['start_s']))
            end = origin+e['start_s']+e['duration_s']
            if end <= loop.time():
                status, error = 'failed', 'Missed event deadline'
            else:
                try:
                    async with AsyncTimeout(deadline=end+.05):
                        await traffic(e,cfg['targets'][e['destination']],metrics,end,context)
                except TimeoutError:
                    status = 'completed' if metrics['bytes_tx']+metrics['bytes_rx'] > 0 else 'failed'
                    error = 'Deadline reached; compare actual and planned bytes'
        except asyncio.CancelledError:
            status, error = 'cancelled', 'Run stopped'
        except Exception as exc:
            status, error = 'failed', str(exc)[:1000]
        finally:
            active.pop(e['event_id'], None)
            actual=metrics['bytes_tx']+metrics['bytes_rx']
            metrics['shortfall_bytes']=max(0,e['planned_bytes']-actual) if started else 0
            if status=='completed' and metrics['shortfall_bytes']:
                error=error or 'Scheduled payload shortfall: %s of %s bytes' % (actual,e['planned_bytes'])
            emit(dict(type='event',event_id=e['event_id'],status=status,actual_end_s=loop.time()-origin if started else None,
                      stop_timestamp=time.time(),error=error,**metrics))
    tasks = [asyncio.create_task(event(e)) for e in cfg['events']]
    all_done = asyncio.gather(*tasks)
    stopper = asyncio.create_task(stop.wait())
    ctl, rpt = asyncio.create_task(control()), asyncio.create_task(reporter())
    try:
        done,_ = await asyncio.wait([all_done,stopper],timeout=max(0,start-time.time())+cfg['duration_s']+5,return_when=asyncio.FIRST_COMPLETED)
        if all_done not in done:
            for task in tasks: task.cancel()
        await all_done
    finally:
        for task in (stopper,ctl,rpt): task.cancel()
        await asyncio.gather(stopper,ctl,rpt,return_exceptions=True)
    emit(dict(type='done'))


def receiver_process(host, tcp, udp, http):
    asyncio.run(receiver(host, tcp, udp, http, reuse_port=True))


def parallel_receiver(args):
    """Supervise independent event loops sharing Linux SO_REUSEPORT sockets."""
    ctx = multiprocessing.get_context('spawn')
    children = [ctx.Process(target=receiver_process,
                args=(args.host,args.tcp_port,args.udp_port,args.http_port))
                for _ in range(args.workers)]
    def stop(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    try:
        for child in children:
            child.start()
        while True:
            for child in children:
                child.join(timeout=.2)
                if child.exitcode is not None:
                    raise RuntimeError('Receiver worker exited: %s' % child.exitcode)
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
        for child in children:
            if child.pid is not None:
                child.join(timeout=5)
                if child.is_alive():
                    child.kill()
                    child.join()


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='command',required=True)
    sub.add_parser('worker')
    r = sub.add_parser('receiver')
    r.add_argument('--host',default='127.0.0.1')
    r.add_argument('--tcp-port',type=int,default=9001)
    r.add_argument('--udp-port',type=int,default=9002)
    r.add_argument('--http-port',type=int,default=8088)
    r.add_argument('--workers',type=int,default=1,help='Independent receiver processes (Linux SO_REUSEPORT)')
    args = p.parse_args()
    if args.command=='receiver' and not 1 <= args.workers <= 64:
        p.error('--workers must be between 1 and 64')
    try:
        if args.command=='receiver' and args.workers > 1:
            parallel_receiver(args)
        else:
            asyncio.run(worker() if args.command=='worker' else receiver(args.host,args.tcp_port,args.udp_port,args.http_port))
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
