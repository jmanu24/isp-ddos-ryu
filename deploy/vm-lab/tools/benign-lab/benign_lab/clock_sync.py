"""Four-timestamp clock probes over an already established agent channel."""
import asyncio
import math
import time
import uuid
from .planner import canonical


def estimate(t1, t2, t3, t4):
    if not all(math.isfinite(v) for v in (t1,t2,t3,t4)) or t3 < t2 or t4 < t1:
        raise ValueError('Invalid clock timestamps')
    delay = (t4-t1)-(t3-t2)
    if delay < -0.001:
        raise ValueError('Clock changed during probe')
    delay = max(0.0,delay)
    return dict(offset_s=((t2-t1)+(t3-t4))/2,round_trip_s=delay,uncertainty_s=delay/2)


def verdict(sample, limit):
    magnitude=abs(sample['offset_s'])
    if magnitude+sample['uncertainty_s'] <= limit:
        return 'synchronized'
    if magnitude-sample['uncertainty_s'] > limit:
        return 'skewed'
    return 'inconclusive'


async def probe_clock(proc, limit, attempts=5, timeout_s=5):
    import json
    samples=[]
    timeouts=0
    for _ in range(attempts):
        nonce=uuid.uuid4().hex
        mono=time.monotonic()
        t1=time.time()
        proc.stdin.write(canonical(dict(type='clock',nonce=nonce))+b'\n')
        await proc.stdin.drain()
        deadline=mono+timeout_s
        try:
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0: raise asyncio.TimeoutError()
                raw=await asyncio.wait_for(proc.stdout.readline(),remaining)
                if not raw: raise RuntimeError('Agent closed its channel during clock synchronization')
                reply=json.loads(raw)
                if reply.get('type')!='clock':
                    raise RuntimeError('Agent does not support clock probe protocol; update worker')
                # A timed-out request may arrive during the next probe. Its
                # timestamps belong to another t1 and must never be reused.
                if reply.get('nonce')==nonce: break
        except asyncio.TimeoutError:
            timeouts+=1
            continue
        t4=time.time()
        elapsed=time.monotonic()-mono
        if abs((t4-t1)-elapsed)>0.01:
            raise RuntimeError('Control node clock changed during synchronization probe')
        samples.append(estimate(t1,reply['received_unix'],reply['sent_unix'],t4))
        await asyncio.sleep(0)
    if not samples:
        raise RuntimeError('Clock synchronization timed out: no matching reply in %d probes (%.1fs each)' % (attempts,timeout_s))
    best=min(samples,key=lambda s:s['round_trip_s'])
    return dict(method='four_timestamps_minimum_rtt',samples=samples,timeouts=timeouts,**best,status=verdict(best,limit),limit_s=limit)
