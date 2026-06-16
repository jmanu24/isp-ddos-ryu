import time


class FlowCollector:

    def __init__(self):

        self.prev_flows = {}

    def process_stats(self, dpid, body):

        flows = []

        now = time.time()

        for stat in body:

            match = stat.match

            src_ip = match.get("ipv4_src", "N/A")
            dst_ip = match.get("ipv4_dst", "N/A")

            proto = match.get("ip_proto", 0)

            src_port = None
            dst_port = None

            if proto == 6:

                src_port = match.get("tcp_src", 0)
                dst_port = match.get("tcp_dst", 0)

            elif proto == 17:

                src_port = match.get("udp_src", 0)
                dst_port = match.get("udp_dst", 0)

            key = (
                dpid,
                src_ip,
                dst_ip,
                proto,
                src_port,
                dst_port
            )

            prev = self.prev_flows.get(
                key,
                {
                    "bytes": stat.byte_count,
                    "packets": stat.packet_count,
                    "time": now
                }
            )

            dt = now - prev["time"]

            if dt <= 0:
                dt = 1

            byte_rate = (
                stat.byte_count -
                prev["bytes"]
            ) / dt

            packet_rate = (
                stat.packet_count -
                prev["packets"]
            ) / dt

            flows.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "src_port": src_port,
                "dst_port": dst_port,
                "byte_rate": byte_rate,
                "packet_rate": packet_rate,
                "bytes": stat.byte_count,
                "packets": stat.packet_count
            })

            self.prev_flows[key] = {
                "bytes": stat.byte_count,
                "packets": stat.packet_count,
                "time": now
            }

        return flows
