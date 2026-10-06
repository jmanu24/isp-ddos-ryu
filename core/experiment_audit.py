"""Structured experimental evidence; logging failures never alter control decisions."""
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
_IMPLEMENTATION=None

KEYS=('SYN_THRESHOLD','UDP_THRESHOLD','ICMP_THRESHOLD','DECISION_THRESHOLD','DIST_PPS_THRESHOLD','DIST_ENTROPY_THRESHOLD','LOW_SLOW_NEW_FLOWS','LOW_SLOW_MOBILE_MAX_PPS','LOW_SLOW_DETECTION_ENABLED','COLLECT_INTERVAL','DETECTION_CROSS_DOMAIN_CORRELATION')

def thresholds(settings):
    values={k:getattr(settings,k) for k in KEYS if hasattr(settings,k)}
    global _IMPLEMENTATION
    if _IMPLEMENTATION is None:
        _IMPLEMENTATION={}
        for relative in ('controller/ryu_controller_2.py','orchestration/controller.py','detection/engine.py','decision/engine.py'):
            try:_IMPLEMENTATION[relative]=hashlib.sha256((Path(__file__).resolve().parents[1]/relative).read_bytes()).hexdigest()
            except OSError:_IMPLEMENTATION[relative]=None
    return dict(values=values,implementation_hashes=_IMPLEMENTATION,hash=hashlib.sha256(json.dumps(dict(values=values,implementation=_IMPLEMENTATION),sort_keys=True).encode()).hexdigest())

def emit(logger,kind,**fields):
    if os.getenv('LAB_AUDIT_ENABLED','false').lower()!='true':return
    try:
        record=dict(schema=1,event_id=uuid.uuid4().hex,timestamp=time.time(),kind=kind,**fields)
        logger.info('LAB_AUDIT '+json.dumps(record,separators=(',',':'),allow_nan=False))
    except Exception:
        # Observability must not interrupt forwarding or mitigation.
        try:logger.warning('LAB_AUDIT_WRITE_FAILED')
        except Exception:pass
