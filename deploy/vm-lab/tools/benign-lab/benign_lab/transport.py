"""Virtual worker pipes multiplexed over one supervised SSH process."""
import asyncio
import json
from .planner import canonical


class WorkerInput:
    def __init__(self,session,key): self.session,self.key=session,key
    def write(self,data):
        for line in data.splitlines():
            if not line: continue
            payload='STOP' if line==b'STOP' else json.loads(line)
            self.session.proc.stdin.write(canonical(dict(worker=self.key,payload=payload))+b'\n')
    async def drain(self): await self.session.proc.stdin.drain()
    def close(self): self.write(b'STOP\n')


class WorkerChannel:
    def __init__(self,session,key):
        self.stdin=WorkerInput(session,key)
        self.stdout=asyncio.StreamReader(limit=32*1024*1024)
        self.stderr=asyncio.StreamReader(limit=32*1024*1024)
        self.returncode=None
        self.exited=asyncio.get_running_loop().create_future()
    async def wait(self): return await asyncio.shield(self.exited)
    def finish(self,code):
        if self.returncode is not None: return
        self.returncode=code
        self.stdout.feed_eof(); self.stderr.feed_eof()
        self.exited.set_result(code)


class SupervisorSession:
    def __init__(self,proc,keys):
        self.proc=proc
        self.channels={k:WorkerChannel(self,k) for k in keys}
        self.stats=dict(frames=0,envelopes=0,bytes=0)
        self.error_task=asyncio.create_task(self.errors())
        self.task=asyncio.create_task(self.pump())
    async def errors(self):
        while True:
            line=await self.proc.stderr.readline()
            if not line:break
            for channel in self.channels.values():
                if channel.returncode is None:channel.stderr.feed_data(line)
    async def pump(self):
        error=None
        try:
            while True:
                line=await self.proc.stdout.readline()
                if not line: break
                msg=json.loads(line)
                if msg.get('type')!='multiplex': raise ValueError('Invalid supervisor response')
                self.stats['frames']+=1
                self.stats['bytes']+=len(line)
                self.stats['envelopes']+=len(msg['items'])
                for item in msg['items']:
                    channel=self.channels[item['worker']]
                    if 'exit_code' in item: channel.finish(item['exit_code'])
                    else: getattr(channel,item['stream']).feed_data(item['line'].encode())
        except Exception as exc:
            error=exc
        finally:
            # A supervisor failure must fail all workers, including channels
            # whose readiness/read calls are still waiting.
            for channel in self.channels.values():
                if error and channel.returncode is None:
                    channel.stderr.feed_data(('Supervisor protocol error: '+str(error)+'\n').encode())
                channel.finish(1)
