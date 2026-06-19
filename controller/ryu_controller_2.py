from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_switch, get_link

import threading

# Forwarding
from forwarding.learning_switch import LearningSwitch

# ── Pipeline layers (Centralized Controller architecture) ──────────────────
# Stage 1 — Telemetry Collection
from telemetry.openflow_adapter import OpenFlowAdapter
from telemetry.mobile_adapter import MobileNetworkAdapter
from telemetry.broadband_adapter import BroadbandAdapter
from telemetry.enterprise_adapter import EnterpriseAdapter
from telemetry.bgp_adapter import BGPPeeringAdapter

# Stage 2 — Multidomain Correlation
from correlation.correlator import MultidomainCorrelator

# Stage 3 — DDoS Detection Engine
from detection.engine import DDoSDetectionEngine

# Stages 4 + 5 — Decision Engine + Orchestration & Control
from orchestration.controller import OrchestrationController
# ──────────────────────────────────────────────────────────────────────────

# Web dashboard
from web.state import dashboard_state
from web.socket_server import start_server, emit_update

import config.settings as settings


class FlowStatsIDS(app_manager.RyuApp):
    """
    Centralized SDN Controller with multidomain DDoS detection.

    This Ryu application is intentionally thin: it owns only the OpenFlow
    protocol interactions (switch features, packet-in, flow/port stats) and
    delegates all business logic to the 5-stage pipeline:

      Telemetry Collection
        └─> Multidomain Correlation
              └─> DDoS Detection Engine
                    └─> Decision Engine
                          └─> Orchestration & Control
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Active datapaths — used to poll flow/port stats
        self.datapaths = {}

        # ── Forwarding ────────────────────────────────────────────────
        self.forwarding = LearningSwitch()

        # ── Stage 1: Telemetry Collection ────────────────────────────
        self.of_adapter = OpenFlowAdapter()

        all_adapters = [
            self.of_adapter,
            MobileNetworkAdapter(),      # stub — wire up ric_endpoint later
            BroadbandAdapter(),          # stub — wire up bng_host later
            EnterpriseAdapter(),         # stub — wire up pe_host later
            BGPPeeringAdapter(),         # stub — wire up router_host later
        ]

        # ── Stages 2-5: Correlation → Detection → Decision → Control ─
        self.correlator  = MultidomainCorrelator()
        self.detector    = DDoSDetectionEngine()
        self.orchestrator = OrchestrationController(all_adapters)

        # ── Monitoring loop ───────────────────────────────────────────
        self.monitor_thread = hub.spawn(self._monitor)

        # ── Web dashboard ─────────────────────────────────────────────
        threading.Thread(target=start_server, daemon=True).start()

        self.logger.info("FlowStats IDS iniciado")

    # ------------------------------------------------------------------
    # TOPOLOGY
    # ------------------------------------------------------------------

    def _update_topology(self):
        try:
            nodes = [
                {"id": str(sw.dp.id), "label": f"s{sw.dp.id}"}
                for sw in get_switch(self, None)
            ]
            links = [
                {"source": str(lk.src.dpid), "target": str(lk.dst.dpid)}
                for lk in get_link(self, None)
            ]
            dashboard_state.update_topology(nodes, links)
            emit_update()
        except Exception as e:
            self.logger.error("Topology update error: %s", e)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        dashboard_state.add_event("Switch agregado a topologia")
        self._update_topology()

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        dashboard_state.add_event("Switch removido de topologia")
        self._update_topology()

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        dashboard_state.add_event("Nuevo enlace detectado")
        self._update_topology()

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        dashboard_state.add_event("Enlace eliminado")
        self._update_topology()

    # ------------------------------------------------------------------
    # SWITCH FEATURES
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        self.datapaths[datapath.id] = datapath

        # Install table-miss flow entry
        self.forwarding.switch_features_handler(datapath)

        # Register datapath with the OpenFlow mitigator
        self.orchestrator.register_datapath(datapath)

        dashboard_state.add_switch(datapath.id)
        dashboard_state.add_event(f"Switch conectado: {datapath.id}")
        emit_update()

        self.logger.info("Switch conectado: %s", datapath.id)

    # ------------------------------------------------------------------
    # PACKET IN
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # ── Stage 1: Telemetry Collection (packet-level) ──────────────
        telemetry_ev = self.of_adapter.on_packet_in(ev.msg)

        if telemetry_ev and telemetry_ev.pps > settings.UDP_THRESHOLD:
            dashboard_state.add_event(
                f"DDoS DETECTADO "
                f"DST={telemetry_ev.dst_ip} "
                f"PPS={telemetry_ev.pps:.2f}"
            )
            emit_update()

        # ── Forwarding ────────────────────────────────────────────────
        self.forwarding.packet_in_handler(ev)

    # ------------------------------------------------------------------
    # MONITOR — periodic pipeline execution
    # ------------------------------------------------------------------

    def _monitor(self):
        while True:
            # Request fresh stats from all connected switches
            for dp in list(self.datapaths.values()):
                try:
                    self._request_flow_stats(dp)
                    self._request_port_stats(dp)
                except Exception as e:
                    self.logger.error("Stats request error: %s", e)

            hub.sleep(settings.COLLECT_INTERVAL)

            # Run the full 5-stage pipeline
            self._run_pipeline()

    def _run_pipeline(self):
        """
        Execute the centralized controller pipeline once per monitoring cycle.

        Stage 1  Telemetry Collection   — drain events from all adapters
        Stage 2  Multidomain Correlation — group by destination IP
        Stage 3  DDoS Detection Engine   — classify attack types
        Stage 4  Decision Engine          — threshold + weighting
        Stage 5  Orchestration & Control  — dispatch mitigation actions
        """
        # Stage 1 — collect from OpenFlow adapter (others return [] for now)
        all_events = self.of_adapter.collect()

        # Stage 2 — correlate across domains
        self.correlator.ingest(all_events)
        correlated = self.correlator.correlate()

        # Release blocks whose flow volume has died down — runs every cycle,
        # even an empty one, since "no traffic at all" is itself the signal
        # that an attack has stopped.
        self.orchestrator.check_unblocks(correlated)

        if not correlated:
            return

        # Stage 3 — detect attack types
        detections = self.detector.analyze(correlated)

        # Stages 4 + 5 — decide and orchestrate
        actions = self.orchestrator.process(detections)

        # Reflect mitigations in the dashboard
        for action in actions:
            msg = (
                f"MITIGACION: {action.action.upper()} "
                f"{action.src_ip} [{action.domain}]"
            )
            dashboard_state.add_event(msg)
            emit_update()
            self.logger.warning(msg)

    # ------------------------------------------------------------------
    # FLOW STATS
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id

        # Stage 1 — push raw stats into the OpenFlow telemetry adapter
        events = self.of_adapter.on_flow_stats(dpid, ev.msg.body)

        # Aggregate totals for the dashboard
        total_bps = sum(e.bps for e in events)
        total_pps = sum(e.pps for e in events)

        dashboard_state.update_stats(dpid, total_bps, total_pps)
        emit_update()

        self.logger.info(
            "SW %s | B/s %.2f | P/s %.2f",
            dpid, total_bps, total_pps
        )

        # Quick dashboard alert (coarse threshold for immediate feedback)
        if total_pps > settings.UDP_THRESHOLD:
            dashboard_state.add_attack(dpid, total_bps, total_pps)
            dashboard_state.add_event(
                f"POSIBLE DDoS SW={dpid} "
                f"B/s={total_bps:.2f} P/s={total_pps:.2f}"
            )
            emit_update()

    # ------------------------------------------------------------------
    # PORT STATS
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        ofproto = ev.msg.datapath.ofproto

        for stat in sorted(ev.msg.body, key=lambda x: x.port_no):

            if stat.port_no == ofproto.OFPP_LOCAL:
                continue

            self.logger.info(
                "PORT SW=%s PORT=%s RX_B=%d TX_B=%d RX_P=%d TX_P=%d "
                "DROP_RX=%d DROP_TX=%d",
                dpid,
                stat.port_no,
                stat.rx_bytes,
                stat.tx_bytes,
                stat.rx_packets,
                stat.tx_packets,
                stat.rx_dropped,
                stat.tx_dropped,
            )

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowStatsRequest(datapath))

    def _request_port_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath.send_msg(
            parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        )
