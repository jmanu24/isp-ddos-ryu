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
from web import metrics

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
        # is_blocked/is_validated are resolved lazily (self.orchestrator
        # doesn't exist yet at this point in __init__) so they must stay
        # lambdas, not bound method references.
        self.forwarding = LearningSwitch(
            is_blocked=lambda dst_ip, dst_port, proto: self.orchestrator.is_blocked_destination(
                dst_ip, dst_port, proto
            ),
            is_validated=lambda dst_ip: self.orchestrator.is_validated_destination(dst_ip),
        )

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
        # Classification happens once per cycle in _run_pipeline(); this
        # handler only collects telemetry, it doesn't raise its own alert.
        self.of_adapter.on_packet_in(ev.msg)

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

        # Surface every detection in the event log, classified — this is
        # the descriptive "what's happening" signal; raw traffic numbers
        # live in Grafana via /metrics instead.
        for d in detections:
            msg = (
                f"ATAQUE DETECTADO: {d.attack_type} "
                f"origen={d.src_ip} destino={d.dst_ip}:{d.dst_port}/{d.protocol} "
                f"[{d.domain}] confianza={d.confidence:.2f}"
            )
            dashboard_state.add_event(msg)
            self.logger.warning(msg)

        # Mark destinations seen clean this cycle as validated — only now
        # can LearningSwitch start caching forwarding rules for them.
        self.orchestrator.validate(correlated, detections)

        # Stages 4 + 5 — decide and orchestrate
        actions = self.orchestrator.process(detections)

        # Reflect mitigations in the dashboard
        for action in actions:
            msg = (
                f"MITIGACION: {action.action.upper()} ({action.attack_type}) "
                f"origen={action.src_ip} destino={action.dst_ip}:{action.dst_port}/{action.protocol} "
                f"[{action.domain}]"
            )
            dashboard_state.add_event(msg)
            self.logger.warning(msg)

        if detections or actions:
            emit_update()

    # ------------------------------------------------------------------
    # FLOW STATS
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id

        # Clean up forwarding rules left behind for destinations already
        # under an active distributed block — runs every cycle, not just
        # at block time, so stragglers from the detection race window
        # eventually get swept too.
        self.orchestrator.sweep_blocked_forwarding(ev.msg.body)

        # Stage 1 — push raw stats into the OpenFlow telemetry adapter
        events = self.of_adapter.on_flow_stats(dpid, ev.msg.body)

        # Traffic numbers go to Prometheus/Grafana, not the console or the
        # event log — classification (Stage 3, in _run_pipeline) is what
        # gets logged as an event.
        total_bps = sum(e.bps for e in events)
        total_pps = sum(e.pps for e in events)
        metrics.update_switch_stats(dpid, total_bps, total_pps)
        dashboard_state.update_stats(dpid, total_bps, total_pps)

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

            # Raw port counters go straight to Prometheus/Grafana — no
            # console dump.
            metrics.update_port_stats(dpid, stat.port_no, stat)

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
