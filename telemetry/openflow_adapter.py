import time
from typing import Dict, List, Tuple

from ryu.lib.packet import packet, ipv4, tcp, udp

import config.settings as settings
from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter
from collectors.flow_collector import FlowCollector
from collectors.ddos_collector import DDoSCollector


_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

# How long a _flow_meta entry is trusted for. Once a (src,dst) pair has a
# cached L3 forwarding rule, traffic between them never triggers another
# packet-in — even if a completely different L4 protocol starts flowing
# through that same cached rule later (e.g. a ping, then minutes later a
# UDP flood between the same two hosts). Without a TTL, flow-stats volume
# would keep getting confidently mislabeled with whatever protocol the
# *first* packet ever seen on that pair happened to be, for as long as the
# rule stays alive (which, under continuous attack traffic, is forever —
# idle_timeout keeps resetting). Past this TTL, an unrefreshed entry is
# distrusted and classification falls back to generic "IP" rather than a
# stale, possibly wrong protocol label. Matches
# settings.VALIDATED_FLOW_HARD_TIMEOUT, which forces the cached rule
# itself to expire and trigger a fresh packet-in before this TTL runs out.
_FLOW_META_TTL = settings.VALIDATED_FLOW_HARD_TIMEOUT


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

            meta = self._fresh_meta(src_ip, dst_ip)
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

        # Fallback for sources this window's aggregation picked up that
        # weren't the one that just triggered _remember_flow_meta above —
        # still better than nothing, since a source typically keeps
        # entering via the same physical port in a static topology.
        fallback_dpid = msg.datapath.id
        fallback_in_port = msg.match["in_port"]

        events = []
        for src_ip, pps in result["src_pps"].items():
            meta = self._fresh_meta(src_ip, result["dst_ip"])
            dpid = meta["dpid"] if meta else fallback_dpid
            in_port = meta["in_port"] if meta else fallback_in_port

            events.append(TelemetryEvent(
                domain=self.domain_name,
                device_id=str(dpid),
                src_ip=src_ip,
                dst_ip=result["dst_ip"],
                dst_port=result["dst_port"],
                protocol=result["protocol"],
                pps=pps,
                bps=pps * bytes_per_packet,
                in_port=in_port,
            ))

        self._pending.extend(events)
        return events

    def _remember_flow_meta(self, msg) -> None:
        """
        Record the L4 protocol/port and ingress (dpid, in_port) for this
        (src_ip, dst_ip) pair so that later, L4-blind flow-stats volume
        events can be tagged correctly, and mitigation can scope a block
        to the switch+port closest to this source instead of the whole
        network.
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
            "dpid": msg.datapath.id,
            "in_port": msg.match["in_port"],
            "timestamp": time.time(),
        }

    def _fresh_meta(self, src_ip: str, dst_ip: str):
        """_flow_meta entry for (src_ip, dst_ip) if it's younger than
        _FLOW_META_TTL, else None."""
        meta = self._flow_meta.get((src_ip, dst_ip))
        if meta and (time.time() - meta["timestamp"]) <= _FLOW_META_TTL:
            return meta
        return None

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
