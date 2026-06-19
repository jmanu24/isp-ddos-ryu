from time import time

from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp


class DDoSCollector:

    def __init__(self):

        self.stats = {}

    def process_packet(self, msg):

        pkt = packet.Packet(msg.data)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if not ip_pkt:
            return None

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        protocol = "IP"
        dst_port = 0

        if tcp_pkt:
            protocol = "TCP"
            dst_port = tcp_pkt.dst_port

        elif udp_pkt:
            protocol = "UDP"
            dst_port = udp_pkt.dst_port

        key = (
            ip_pkt.src,
            ip_pkt.dst,
            dst_port,
            protocol
        )

        now = time()

        if key not in self.stats:

            self.stats[key] = {
                "packets": 1,
                "bytes": len(msg.data),
                "timestamp": now
            }

            return None

        entry = self.stats[key]

        entry["packets"] += 1
        entry["bytes"] += len(msg.data)

        delta = now - entry["timestamp"]

        if delta < 1:
            return None

        result = {
            "src_ip": ip_pkt.src,
            "dst_ip": ip_pkt.dst,
            "dst_port": dst_port,
            "protocol": protocol,
            "pps": entry["packets"] / delta,
            "bps": entry["bytes"] / delta
        }

        entry["packets"] = 0
        entry["bytes"] = 0
        entry["timestamp"] = now

        return result
