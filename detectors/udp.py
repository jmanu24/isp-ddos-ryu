from core.models import DetectionEvent
from config.settings import UDP_THRESHOLD

class UDPDetector:

    def __init__(self):
        self.counter = {}

    def detect(self, event):

        if event.protocol != 17:
            return None

        self.counter[event.src_ip] = self.counter.get(event.src_ip, 0) + 1

        if self.counter[event.src_ip] > UDP_THRESHOLD:

            return DetectionEvent(
                detector="udp",
                src_ip=event.src_ip,
                score=0.8
            )

        return None
