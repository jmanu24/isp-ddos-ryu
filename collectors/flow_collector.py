import time


class FlowCollector:

    def __init__(self):
        self.prev_stats = {}

    def process_stats(self, dpid, body):

        total_bytes = 0
        total_packets = 0

        for stat in body:
            total_bytes += stat.byte_count
            total_packets += stat.packet_count

        prev = self.prev_stats.get(
            dpid,
            {
                "bytes": 0,
                "packets": 0,
                "time": time.time()
            }
        )

        now = time.time()

        dt = now - prev["time"]

        if dt <= 0:
            dt = 1

        byte_rate = (total_bytes - prev["bytes"]) / dt
        packet_rate = (total_packets - prev["packets"]) / dt

        self.prev_stats[dpid] = {
            "bytes": total_bytes,
            "packets": total_packets,
            "time": now
        }

        return {
            "byte_rate": byte_rate,
            "packet_rate": packet_rate
        }
