from .base import BaseDetector


class LowSlowDetector(BaseDetector):

    def __init__(self):
        self.byte_threshold = 500
        self.packet_threshold = 20

    def detect(self, flow):

        if flow.packets < self.packet_threshold and flow.bytes > self.byte_threshold:

            return {
                "type": "LOW_SLOW",
                "src_ip": flow.src_ip,
                "score": flow.bytes
            }

        return None
