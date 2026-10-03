"""Standalone per-VM worker supervisor. Python 3.8+, no third-party modules.

Each worker retains its own process/network namespace and clock protocol.
Closing the SSH input stops every child; child exits and diagnostics are framed.
"""
import asyncio
import json
import os
import signal
import sys


def emit(value):
    print(json.dumps(value, separators=(',', ':')), flush=True)


async def supervise():
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=32*1024*1024)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    cfg = json.loads(await reader.readline())
    children, tasks = {}, []
    queue = asyncio.Queue(maxsize=1000)
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    async def output():
        while True:
            item = await queue.get()
            batch = [item]
            await asyncio.sleep(.02)
            while not queue.empty() and len(batch) < 256:
                batch.append(queue.get_nowait())
            emit(dict(type='multiplex', items=batch))
            for _ in batch: queue.task_done()

    async def pump(key, proc, stream):
        while True:
            line = await getattr(proc, stream).readline()
            if not line: break
            item = dict(worker=key, stream=stream, line=line.decode(errors='replace'))
            # Clock and readiness must not incur the telemetry batching delay.
            if stream == 'stdout' and json.loads(line).get('type') in ('clock','ready','fatal'):
                emit(dict(type='multiplex', items=[item]))
            else:
                await queue.put(item)

    async def watch(key, proc):
        await proc.wait()
        await queue.put(dict(worker=key, exit_code=proc.returncode))

    async def launch(spec):
        key = spec['key']
        if key in children: raise ValueError('Duplicate worker key')
        proc = await asyncio.create_subprocess_exec(*spec['argv'], stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                start_new_session=True, limit=32*1024*1024)
        children[key] = proc
        pumps = [asyncio.create_task(pump(key,proc,s)) for s in ('stdout','stderr')]
        tasks.extend(pumps)
        async def complete():
            await asyncio.gather(*pumps)
            await watch(key,proc)
        tasks.append(asyncio.create_task(complete()))
        proc.stdin.write((json.dumps(spec['config'])+'\n').encode())
        await proc.stdin.drain()

    async def control():
        while True:
            raw = await reader.readline()
            if not raw or raw.strip() == b'STOP': break
            msg = json.loads(raw)
            proc = children.get(msg['worker'])
            if proc is None: raise ValueError('Unknown worker key')
            if proc.returncode is not None: continue
            payload = msg['payload']
            proc.stdin.write((payload if isinstance(payload,str) else json.dumps(payload)).encode()+b'\n')
            await proc.stdin.drain()
        stop.set()

    writer = asyncio.create_task(output())
    ctl = stopped = completed = None
    try:
        await asyncio.gather(*(launch(spec) for spec in cfg['workers']))
        ctl = asyncio.create_task(control())
        stopped = asyncio.create_task(stop.wait())
        completed = asyncio.gather(*tasks)
        done,_ = await asyncio.wait([stopped,completed,ctl,writer],return_when=asyncio.FIRST_COMPLETED)
        if writer in done: await writer
        if ctl in done: await ctl
        if completed in done: await completed
        stopped.cancel()
        await asyncio.gather(stopped,return_exceptions=True)
    finally:
        for proc in children.values():
            if proc.returncode is None:
                try:
                    proc.stdin.write(b'STOP\n'); await proc.stdin.drain(); proc.stdin.close()
                except (OSError,ConnectionError): pass
        async def reap(proc):
            if proc.returncode is not None: return
            try: await asyncio.wait_for(proc.wait(),1.5)
            except asyncio.TimeoutError:
                try: os.killpg(proc.pid,signal.SIGTERM)
                except ProcessLookupError: pass
                try: await asyncio.wait_for(proc.wait(),1)
                except asyncio.TimeoutError:
                    try: os.killpg(proc.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                    await proc.wait()
        await asyncio.gather(*(reap(p) for p in children.values()))
        # A broken output pipe can leave telemetry producers blocked on the
        # bounded queue. Reaping children must still finish without a reader.
        try: await asyncio.wait_for(asyncio.gather(*tasks,return_exceptions=True),2)
        except asyncio.TimeoutError: pass
        if completed:await asyncio.gather(completed,return_exceptions=True)
        if stopped:
            stopped.cancel();await asyncio.gather(stopped,return_exceptions=True)
        try: await asyncio.wait_for(queue.join(),1)
        except asyncio.TimeoutError: pass
        if ctl: ctl.cancel()
        writer.cancel()
        await asyncio.gather(writer,*([ctl] if ctl else []),return_exceptions=True)


if __name__ == '__main__':
    asyncio.run(supervise())
