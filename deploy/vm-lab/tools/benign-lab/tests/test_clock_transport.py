import asyncio,json,time
from benign_lab.clock_sync import probe_clock

class Pipe:
    def __init__(self,reader):self.reader=reader;self.previous=None;self.calls=0
    def write(self,data):
        self.calls+=1
        nonce=json.loads(data)['nonce']
        if self.calls==1:self.previous=nonce;return
        now=time.time()
        for n in (self.previous,nonce):
            self.reader.feed_data((json.dumps(dict(type='clock',nonce=n,received_unix=now,sent_unix=now))+'\n').encode())
    async def drain(self):pass

def test_probe_recovers_timeout_and_discards_stale_nonce():
    async def check():
        reader=asyncio.StreamReader()
        proc=type('Proc',(),{})();proc.stdout=reader;proc.stdin=Pipe(reader)
        result=await probe_clock(proc,.5,attempts=2,timeout_s=.02)
        assert result['timeouts']==1
        assert len(result['samples'])==1
        assert result['status']=='synchronized'
    asyncio.run(check())

def test_probe_timeout_has_actionable_error():
    async def check():
        reader=asyncio.StreamReader()
        proc=type('Proc',(),{})();proc.stdout=reader;proc.stdin=Pipe(reader)
        import pytest
        with pytest.raises(RuntimeError,match='no matching reply'):
            await probe_clock(proc,.5,attempts=1,timeout_s=.01)
    asyncio.run(check())

def test_closed_clock_channel_is_reported():
    async def check():
        reader=asyncio.StreamReader();reader.feed_eof()
        proc=type('Proc',(),{})();proc.stdout=reader;proc.stdin=Pipe(reader)
        import pytest
        with pytest.raises(RuntimeError,match='closed its channel'):
            await probe_clock(proc,.5,attempts=1,timeout_s=.01)
    asyncio.run(check())
