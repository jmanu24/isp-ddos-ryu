"""Bounded idle connections; event concurrency and deadlines remain unchanged."""
import asyncio
import time


async def close_writer(writer):
    writer.close()
    try: await asyncio.wait_for(writer.wait_closed(),.2)
    except (OSError,ConnectionError,asyncio.TimeoutError):
        writer.transport.abort()


class ConnectionPool:
    def __init__(self,options):
        self.options=options
        self.idle={}
        self.writers=set()
        self.opened=0; self.reused=0; self.discarded=0
    def key(self,event,target,source):
        return (source,event['source'],target['host'],event['wire_protocol'],
                target['http_port' if event['wire_protocol']=='http' else 'tcp_port'],
                event['direction'],event.get('application',''))
    async def acquire(self,key):
        items=self.idle.setdefault(key,[])
        while items:
            when,reader,writer=items.pop()
            if time.monotonic()-when<self.options.get('idle_ttl_s',20) and not reader.at_eof() and not writer.is_closing():
                self.reused+=1
                return reader,writer,True
            await self.discard(writer)
        source,_,host,_,port,_,_=key
        reader,writer=await asyncio.wait_for(asyncio.open_connection(host,port,local_addr=(source,0) if source else None),3)
        self.writers.add(writer); self.opened+=1
        return reader,writer,False
    async def discard(self,writer):
        self.writers.discard(writer); self.discarded+=1
        await close_writer(writer)
    async def release(self,key,reader,writer):
        items=self.idle.setdefault(key,[])
        count=sum(len(v) for v in self.idle.values())
        if len(items)>=self.options.get('max_idle_per_key',2) or count>=self.options.get('max_idle_total',128) or reader.at_eof() or writer.is_closing():
            await self.discard(writer)
        else: items.append((time.monotonic(),reader,writer))
    def stats(self):
        return dict(opened=self.opened,reused=self.reused,discarded=self.discarded,
                    open_connections=len(self.writers),idle_connections=sum(len(v) for v in self.idle.values()))
    async def close(self):
        self.idle.clear()
        await asyncio.gather(*(close_writer(w) for w in list(self.writers)),return_exceptions=True)
        self.writers.clear()
