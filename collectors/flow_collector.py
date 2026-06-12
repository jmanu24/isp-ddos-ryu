from ryu.lib.packet import packet
from ryu.lib.packet import ipv4

from core.models import FlowEvent


class FlowCollector:

    def collect(self, msg):

        pkt = packet.Packet(msg.data)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if not ip_pkt:
            return None

        return FlowEvent(
            src_ip=ip_pkt.src,
            dst_ip=ip_pkt.dst,
            protocol=ip_pkt.proto,
            packets=1,
            bytes=len(msg.data),
            flow_id=f"{ip_pkt.src}-{ip_pkt.dst}-{ip_pkt.proto}"
        )
