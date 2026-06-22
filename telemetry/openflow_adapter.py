import time
from typing import Dict, List, Optional, Tuple

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

    def __init__(self, is_host_port=None):
        self._flow_collector = FlowCollector()
        self._ddos_collector = DDoSCollector()
        self._pending: List[TelemetryEvent] = []
        # (src_ip, dst_ip) -> {"protocol": str, "dst_port": int, "dpid",
        # "in_port"}, learned from packet-in. protocol/dst_port/timestamp
        # refresh on every sighting regardless of where it came from;
        # dpid/in_port only ever get set from a confirmed genuine HOST
        # port (see is_host_port below) and then stay sticky — a later
        # sighting of the same pair via an inter-switch link or the
        # router's own interface (which happens for every cross-subnet
        # attack, at the victim's switch) never overwrites a good
        # location with the wrong end of the path.
        self._flow_meta: Dict[Tuple[str, str], dict] = {}
        # Optional Callable[[dpid, in_port], bool] — True only for a port
        # a real host is directly attached to (LearningSwitch.is_host_port).
        # None means "trust every sighting" (used in tests / when this
        # filtering isn't wired up).
        self._is_host_port = is_host_port
        # dst_ip -> count of currently-stalled (old, low-byte) flows
        # toward it, accumulated across all switches this cycle — see
        # FlowCollector.count_low_volume_flows.
        self._low_volume_flow_counts: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Push handlers — called from Ryu event callbacks
    # ------------------------------------------------------------------

    def on_flow_stats(self, dpid, body) -> List[TelemetryEvent]:
        """
        Process an OFPFlowStatsReply body and convert flows to TelemetryEvents.
        Called by the controller's flow_stats_reply_handler.
        """
        for dst_ip, count in self._flow_collector.count_low_volume_flows(body).items():
            self._low_volume_flow_counts[dst_ip] = (
                self._low_volume_flow_counts.get(dst_ip, 0) + count
            )

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
        Record the L4 protocol/port for this (src_ip, dst_ip) pair so
        that later, L4-blind flow-stats volume events can be tagged
        correctly — refreshed on every sighting, regardless of which
        switch/port it came from.

        Also records its ingress (dpid, in_port), but ONLY from a
        confirmed genuine host port, and only ever once: a packet
        between two hosts on different subnets triggers packet-in at
        BOTH the attacker's switch (real host port) and the victim's
        switch (the router's port there, since the packet arrives via
        the router) — recording indiscriminately would let whichever of
        those gets processed last win, which for a cross-subnet attack
        could easily be the victim's own router-facing port. Once a good
        location is set it's never downgraded by a later non-host-port
        sighting of the same pair.
        """
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if tcp_pkt and (tcp_pkt.bits & tcp.TCP_RST):
            # Same reasoning as DDoSCollector: a victim's RST reply isn't
            # part of any flood — don't let it tag this (src,dst) pair's
            # metadata, or later flow-stats volume for the reply direction
            # would inherit a misleading "TCP" classification from it.
            return

        if tcp_pkt:
            # Same SYN-vs-established distinction as DDoSCollector — only
            # a bare SYN (no ACK) is a connection attempt worth feeding
            # into SYN_FLOOD; established-connection traffic shouldn't
            # keep tagging this pair's flow-stats volume as "the same
            # attack" once the handshake is done.
            is_bare_syn = (tcp_pkt.bits & tcp.TCP_SYN) and not (tcp_pkt.bits & tcp.TCP_ACK)
            proto = "TCP_SYN" if is_bare_syn else "TCP"
            dst_port = tcp_pkt.dst_port
        elif udp_pkt:
            proto, dst_port = "UDP", udp_pkt.dst_port
        elif ip_pkt.proto == 1:
            proto, dst_port = "ICMP", 0
        else:
            proto, dst_port = "IP", 0

        key = (ip_pkt.src, ip_pkt.dst)
        meta = self._flow_meta.setdefault(key, {
            "protocol": proto, "dst_port": dst_port,
            "dpid": None, "in_port": None, "timestamp": 0.0,
        })
        meta["protocol"] = proto
        meta["dst_port"] = dst_port
        meta["timestamp"] = time.time()

        dpid, in_port = msg.datapath.id, msg.match["in_port"]

        if self._is_host_port is None or self._is_host_port(dpid, in_port):
            meta["dpid"] = dpid
            meta["in_port"] = in_port

    def _fresh_meta(self, src_ip: str, dst_ip: str):
        """_flow_meta entry for (src_ip, dst_ip) if it's younger than
        _FLOW_META_TTL, else None."""
        meta = self._flow_meta.get((src_ip, dst_ip))
        if meta and (time.time() - meta["timestamp"]) <= _FLOW_META_TTL:
            return meta
        return None

    def collect_low_volume_flow_counts(self) -> Dict[str, int]:
        """Drain and return this cycle's dst_ip -> stalled-flow-count
        accumulated across all switches, for low-and-slow detection."""
        counts = self._low_volume_flow_counts
        self._low_volume_flow_counts = {}
        return counts

    def get_source_ingress(self, src_ip: str, dst_ip: str) -> Tuple[Optional[int], Optional[int]]:
        """
        (dpid, in_port) of the genuine HOST port this (src_ip, dst_ip)
        pair was confirmed entering on, from packet-in — works even when
        src_ip is spoofed/fabricated, since it reflects where the packet
        physically arrived, not an ARP-learned host location (a spoofed
        IP never ARPs, so LearningSwitch.get_host_location would never
        resolve it). Used to scope a distributed attack's block to the
        exact switch+port that source's traffic is actually coming
        through — NEVER network-wide, so this returns None, None (no
        fallback) whenever no confirmed host-port sighting exists yet,
        even if this pair has been seen via an inter-switch or router
        port (see _remember_flow_meta).
        """
        meta = self._fresh_meta(src_ip, dst_ip)
        if meta and meta["dpid"] is not None:
            return meta["dpid"], meta["in_port"]
        return None, None

    def get_connection_port_counts(self) -> Dict[Tuple[str, str], dict]:
        """
        (src_ip, dst_ip) -> {"count", "dst_port", "protocol"} — for
        single-source low-and-slow detection (many real connections from
        one attacker, all collapsed into one L3 forwarding rule, so
        OpenFlow flow stats alone can't tell them apart; packet-in is the
        only place each connection's own src_port/dst_port is visible).
        """
        return self._ddos_collector.get_connection_port_counts()

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
