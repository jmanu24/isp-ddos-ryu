from core.models import DetectionEvent
from config.settings import ICMP_THRESHOLD

class ICMPDetector:

    def __init__(self):
        self.counter = {}

    def detect(self, event):

        if event.protocol != 1:
            return None

        self.counter[event.src_ip] = self.counter.get(event.src_ip, 0) + 1

        if self.counter[event.src_ip] > ICMP_THRESHOLD:

            return DetectionEvent(
                detector="icmp",
                src_ip=event.src_ip,
                score=0.7
            )

        return None
