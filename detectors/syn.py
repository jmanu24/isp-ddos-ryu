from collections import defaultdict
from core.models import DetectionEvent
from config.settings import SYN_THRESHOLD

class SYNDetector:
    def __init__(self):
        self.syn = defaultdict(int)
        self.ack = defaultdict(int)

    def detect(self, event):

        key = event.src_ip + "-" + event.dst_ip

        if event.protocol != 6:
            return None

        self.syn[key] += 1

        ratio = self.syn[key] / max(self.ack[key], 1)

        if ratio > SYN_THRESHOLD:

            return DetectionEvent(
                detector="syn",
                src_ip=event.src_ip,
                score=0.9
            )
        return None
