from core.models import DetectionEvent
from config.settings import LOW_SLOW_NEW_FLOWS, LOW_SLOW_MIN_BYTES

class LowSlowDetector:

    def __init__(self):
        self.flows = {}

    def detect(self, event):

        f = self.flows.get(event.src_ip, {
            "flows": 0,
            "bytes": 0
        })

        f["flows"] += 1
        f["bytes"] += event.bytes

        self.flows[event.src_ip] = f

        if (
            f["flows"] > LOW_SLOW_NEW_FLOWS and
            f["bytes"] < LOW_SLOW_MIN_BYTES
        ):
            return DetectionEvent(
                detector="low_slow",
                src_ip=event.src_ip,
                score=0.95
            )

        return None
