from .base import BaseDetector


class ICMPDetector(BaseDetector):

    def __init__(self):
        self.threshold = 150

    def detect(self, flow):

        if flow.protocol != 1:
            return None

        if flow.packets > self.threshold:

            return {
                "type": "ICMP_FLOOD",
                "src_ip": flow.src_ip,
                "score": flow.packets
            }

        return None
