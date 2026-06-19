from typing import Dict, List, Tuple

from ryu.lib.packet import packet, ipv4, tcp, udp

from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter
from collectors.flow_collector import FlowCollector
from collectors.ddos_collector import DDoSCollector


_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


class OpenFlowAdapter(DomainAdapter):
    """
    Telemetry adapter for the OpenFlow / SDN domain.

    Wraps the existing FlowCollector (periodic per-flow stats via
    OFPFlowStatsReply) and DDoSCollector (real-time packet-in analysis)
    to produce normalized TelemetryEvents for the Correlation layer.

    Forwarding flow rules are installed at L3 only (src/dst IP), so
    OFPFlowStatsReply carries no L4 detail. To keep attack classification
    and mitigation L4-aware anyway, this adapter remembers the protocol/
    dst_port seen on the first packet of each (src_ip, dst_ip) pair (via
    packet-in) and reapplies it to the bulk volume events that come later
    from flow stats.

    Mitigation for this domain is handled by OpenFlowMitigator, which
    needs a live datapath reference — so apply_mitigation() is intentionally
    a no-op here.
    """

    domain_name = "openflow"

    def __init__(self):
        self._flow_collector = FlowCollector()
        self._ddos_collector = DDoSCollector()
        self._pending: List[TelemetryEvent] = []
        # (src_ip, dst_ip) -> {"protocol": str, "dst_port": int}, learned
        # from the first packet-in of each flow.
        self._flow_meta: Dict[Tuple[str, str], dict] = {}

    # ------------------------------------------------------------------
    # Push handlers — called from Ryu event callbacks
    # ------------------------------------------------------------------

    def on_flow_stats(self, dpid, body) -> List[TelemetryEvent]:
        """
        Process an OFPFlowStatsReply body and convert flows to TelemetryEvents.
        Called by the controller's flow_stats_reply_handler.
        """
        flows = self._flow_collector.process_stats(dpid, body)
        events: List[TelemetryEvent] = []

        for flow in flows:
            src_ip = flow.get("src_ip") or "0.0.0.0"
            dst_ip = flow.get("dst_ip") or "0.0.0.0"

            meta = self._flow_meta.get((src_ip, dst_ip))
            if meta:
                proto = meta["protocol"]
                dst_port = meta["dst_port"]
            else:
                proto = _PROTO_NAMES.get(flow["protocol"], "IP")
                dst_port = flow.get("dst_port", 0)

            ev = TelemetryEvent(
                domain=self.domain_name,
                device_id=str(dpid),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                pps=flow["packet_rate"],
                bps=flow["byte_rate"],
            )
            events.append(ev)

        self._pending.extend(events)
        return events

    def on_packet_in(self, msg) -> List[TelemetryEvent]:
        """
        Process a packet-in message for per-destination DDoS metrics.
        Called by the controller's packet_in_handler.

        Returns one TelemetryEvent per distinct source IP seen toward this
        destination during the window — not a single aggregate event —
        so the Correlation/Detection layers can compute source-IP entropy
        for distributed/spoofed-source attacks.
        """
        self._remember_flow_meta(msg)

        result = self._ddos_collector.process_packet(msg)
        if not result:
            return []

        # Distribute the window's aggregate bps proportionally across
        # sources by their share of packets, since bytes aren't tracked
        # per-source.
        bytes_per_packet = result["bps"] / result["pps"] if result["pps"] else 0.0

        events = [
            TelemetryEvent(
                domain=self.domain_name,
                device_id="packet_in",
                src_ip=src_ip,
                dst_ip=result["dst_ip"],
                dst_port=result["dst_port"],
                protocol=result["protocol"],
                pps=pps,
                bps=pps * bytes_per_packet,
            )
            for src_ip, pps in result["src_pps"].items()
        ]

        self._pending.extend(events)
        return events

    def _remember_flow_meta(self, msg) -> None:
        """
        Record the L4 protocol/port for this (src_ip, dst_ip) pair so that
        later, L4-blind flow-stats volume events can be tagged correctly.
        """
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if tcp_pkt:
            proto, dst_port = "TCP", tcp_pkt.dst_port
        elif udp_pkt:
            proto, dst_port = "UDP", udp_pkt.dst_port
        elif ip_pkt.proto == 1:
            proto, dst_port = "ICMP", 0
        else:
            proto, dst_port = "IP", 0

        self._flow_meta[(ip_pkt.src, ip_pkt.dst)] = {
            "protocol": proto,
            "dst_port": dst_port,
        }

    # ------------------------------------------------------------------
    # DomainAdapter interface
    # ------------------------------------------------------------------

    def collect(self) -> List[TelemetryEvent]:
        """Drain and return accumulated events."""
        events = self._pending.copy()
        self._pending.clear()
        return events

    def apply_mitigation(self, action: MitigationAction) -> bool:
        # OpenFlow mitigation requires a live datapath — handled by
        # OpenFlowMitigator in the Orchestration layer.
        return False
