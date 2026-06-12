from .base import BaseDetector


class SYNDetector(BaseDetector):

    def __init__(self):
        self.threshold = 200  # packets per flow window

    def detect(self, flow):

        if flow.protocol != 6:  # TCP
            return None

        if flow.packets > self.threshold:

            return {
                "type": "SYN_FLOOD",
                "src_ip": flow.src_ip,
                "score": flow.packets
            }

        return None
