from typing import List, Optional

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

    Mitigation for this domain is handled by OpenFlowMitigator, which
    needs a live datapath reference — so apply_mitigation() is intentionally
    a no-op here.
    """

    domain_name = "openflow"

    def __init__(self):
        self._flow_collector = FlowCollector()
        self._ddos_collector = DDoSCollector()
        self._pending: List[TelemetryEvent] = []

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
            proto = _PROTO_NAMES.get(flow["protocol"], "IP")
            ev = TelemetryEvent(
                domain=self.domain_name,
                device_id=str(dpid),
                src_ip=flow.get("src_ip") or "0.0.0.0",
                dst_ip=flow.get("dst_ip") or "0.0.0.0",
                dst_port=flow.get("dst_port", 0),
                protocol=proto,
                pps=flow["packet_rate"],
                bps=flow["byte_rate"],
            )
            events.append(ev)

        self._pending.extend(events)
        return events

    def on_packet_in(self, msg) -> Optional[TelemetryEvent]:
        """
        Process a packet-in message for per-destination DDoS metrics.
        Called by the controller's packet_in_handler.
        """
        result = self._ddos_collector.process_packet(msg)
        if not result:
            return None

        ev = TelemetryEvent(
            domain=self.domain_name,
            device_id="packet_in",
            src_ip=result["src_ip"],
            dst_ip=result["dst_ip"],
            dst_port=result["dst_port"],
            protocol=result["protocol"],
            pps=result["pps"],
            bps=result["bps"],
        )
        self._pending.append(ev)
        return ev

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
