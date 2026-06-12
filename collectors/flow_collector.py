from collections import defaultdict

class FlowCollector:
    def __init__(self):
        self.history = defaultdict(list)

    def update(self, flow_id, packets):
        h = self.history[flow_id]
        h.append(packets)

        if len(h) > 20:
            h.pop(0)

        return h
