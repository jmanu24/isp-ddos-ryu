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


async def probe_clock(proc, limit, attempts=5):
    import json
    samples=[]
    for _ in range(attempts):
        nonce=uuid.uuid4().hex
        mono=time.monotonic()
        t1=time.time()
        proc.stdin.write(canonical(dict(type='clock',nonce=nonce))+b'\n')
        await proc.stdin.drain()
        raw=await asyncio.wait_for(proc.stdout.readline(),5)
        t4=time.time()
        elapsed=time.monotonic()-mono
        if abs((t4-t1)-elapsed)>0.01:
            raise RuntimeError('Control node clock changed during synchronization probe')
        reply=json.loads(raw)
        if reply.get('type')!='clock' or reply.get('nonce')!=nonce:
            raise RuntimeError('Agent does not support clock probe protocol; update worker')
        samples.append(estimate(t1,reply['received_unix'],reply['sent_unix'],t4))
        await asyncio.sleep(0)
    best=min(samples,key=lambda s:s['round_trip_s'])
    return dict(method='four_timestamps_minimum_rtt',samples=samples,**best,status=verdict(best,limit),limit_s=limit)
