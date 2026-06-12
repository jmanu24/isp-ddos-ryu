from .base import BaseDetector


class UDPDetector(BaseDetector):

    def __init__(self):
        self.threshold = 300

    def detect(self, flow):

        if flow.protocol != 17:
            return None

        if flow.packets > self.threshold:

            return {
                "type": "UDP_FLOOD",
                "src_ip": flow.src_ip,
                "score": flow.packets
            }

        return None
