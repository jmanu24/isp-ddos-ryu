import logging
from collections import defaultdict
from typing import Dict

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

# force=True re-applies this format even though Ryu's own startup already
# attached handlers to the root logger — without it, basicConfig() would be
# a no-op and every self.logger.* call below would keep printing without a
# timestamp.
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
    force=True,
)

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
        # is_blocked/is_validated/is_interswitch_port are resolved lazily
        # (self.orchestrator doesn't exist yet at this point in __init__)
        # so they must stay lambdas, not bound method references.
        self.forwarding = LearningSwitch(
            is_blocked=lambda src_ip, dst_ip, dst_port, proto: self.orchestrator.is_blocked(
                src_ip, dst_ip, dst_port, proto
            ),
            is_validated=lambda dst_ip: self.orchestrator.is_validated_destination(dst_ip),
            is_interswitch_port=lambda dpid, port: self.orchestrator.is_interswitch_port(dpid, port),
            logger=self.logger,
        )

        # ── Stage 1: Telemetry Collection ────────────────────────────
        self.of_adapter = OpenFlowAdapter(is_host_port=self.forwarding.is_host_port)

        # MobileNetworkAdapter is real now (real E2/KPM pipeline via
        # simulation/parse_xapp_kpm_log.py's output CSV — see that
        # module and telemetry/mobile_adapter.py's docstring). The
        # other three remain stubs.
        self.all_adapters = [
            self.of_adapter,
            MobileNetworkAdapter(logger=self.logger),
            BroadbandAdapter(),          # stub — wire up bng_host later
            EnterpriseAdapter(),         # stub — wire up pe_host later
            BGPPeeringAdapter(),         # stub — wire up router_host later
        ]

        # ── Stages 2-5: Correlation → Detection → Decision → Control ─
        self.correlator  = MultidomainCorrelator()
        self.detector    = DDoSDetectionEngine()
        self.orchestrator = OrchestrationController(
            self.all_adapters,
            locate_host=self.forwarding.get_host_location,
            locate_source_ingress=self.of_adapter.get_source_ingress,
            yield_fn=lambda: hub.sleep(0),
            logger=self.logger,
        )

        # ── Monitoring loop ───────────────────────────────────────────
        self.monitor_thread = hub.spawn(self._monitor)

        # ── Web dashboard ─────────────────────────────────────────────
        threading.Thread(target=start_server, daemon=True).start()

        self.logger.info("FlowStats IDS started")

    # ------------------------------------------------------------------
    # TOPOLOGY
    # ------------------------------------------------------------------

    def _update_topology(self):
        try:
            nodes = [
                {"id": str(sw.dp.id), "label": f"s{sw.dp.id}", "group": "switch"}
                for sw in get_switch(self, None)
            ]
            raw_links = get_link(self, None)
            links = [
                {"source": str(lk.src.dpid), "target": str(lk.dst.dpid)}
                for lk in raw_links
            ]

            # Hosts LearningSwitch has confirmed an edge-port location for
            # — drawn as extra nodes linked to the switch they're attached
            # to, so the graph isn't just switches floating with no leaves.
            # Router/gateway interfaces (always x.x.x.1 by this project's
            # topology convention) are skipped — they clutter the graph
            # with one node per subnet for what's conceptually one device.
            for host in self.forwarding.get_known_hosts():
                if host["ip"].endswith(".1"):
                    continue

                host_id = f"host-{host['ip']}"
                nodes.append({"id": host_id, "label": host["ip"], "group": "host"})
                links.append({"source": host_id, "target": str(host["dpid"])})

            dashboard_state.update_topology(nodes, links)
            emit_update()

            # Every (dpid, port_no) on either side of a discovered switch-
            # switch link — mitigation must never trust one of these as
            # "the port closest to the attacker": a packet with no
            # matching flow rule triggers packet-in on EVERY switch it
            # passes through, not just the one nearest the source, so the
            # ingress info recorded for an intermediate hop's uplink port
            # is meaningless for scoping a block.
            interswitch_ports = set()
            for lk in raw_links:
                interswitch_ports.add((lk.src.dpid, lk.src.port_no))
                interswitch_ports.add((lk.dst.dpid, lk.dst.port_no))
            self.orchestrator.update_interswitch_ports(interswitch_ports)
        except Exception as e:
            self.logger.error("Topology update error: %s", e)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        dashboard_state.add_event("Switch added to topology")
        self._update_topology()

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        dashboard_state.add_event("Switch removed from topology")
        self._update_topology()

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        dashboard_state.add_event("New link detected")
        self._update_topology()

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        dashboard_state.add_event("Link removed")
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
        dashboard_state.add_event(f"Switch connected: {datapath.id}")
        emit_update()

        self.logger.info("Switch connected: %s", datapath.id)

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

            # Refresh hosts on the topology graph — switch/link events
            # alone wouldn't pick up a newly-learned host location.
            self._update_topology()

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
        # Stage 1 — collect from every registered domain adapter (stubs
        # return [] until wired up; MobileNetworkAdapter is real now).
        # Isolated per-adapter so one domain failing (e.g. its CSV not
        # existing yet, or a stub's TODO path) doesn't take down the
        # whole pipeline cycle for every other domain.
        all_events = []
        for adapter in self.all_adapters:
            try:
                all_events.extend(adapter.collect())
            except Exception as e:
                self.logger.error("Telemetry collect error (%s): %s", adapter.domain_name, e)

        # Stage 2 — correlate across domains
        self.correlator.ingest(all_events)
        correlated = self.correlator.correlate()

        # Release blocks whose flow volume has died down — driven by the
        # drop rules' own counters (sampled in flow_stats_reply_handler),
        # not by `correlated`, since a blocked flow's packets never reach
        # this pipeline's telemetry again. Returned (not logged internally)
        # so it goes through the same MITIGATION dashboard/logger line as
        # every other domain's actions below.
        openflow_unblock_actions = self.orchestrator.check_unblocks()

        # Mobile-domain blocks unblock off this cycle's own telemetry
        # instead (see check_mobile_unblocks's docstring) -- a RAN-side
        # throttle doesn't make the UE's traffic vanish from `correlated`
        # the way an openflow drop rule does. Same return-don't-log
        # convention as openflow_unblock_actions above.
        mobile_unblock_actions = self.orchestrator.check_mobile_unblocks(correlated)

        # Stage 3 — detect attack types. Low-and-slow is checked
        # independently of `correlated`/pps-based detection — it's a flow
        # *count* signature (many stalled connections), not a volumetric
        # one, so it can fire even on a cycle with no other traffic. A
        # destination/pair already flagged by a volumetric flood this
        # cycle is excluded from the low-and-slow checks — a fast flood
        # whose tool randomizes its source port per packet (hping3
        # --flood does) looks just like "many distinct connections"
        # otherwise, and shouldn't get double-reported as LOW_SLOW too.
        flood_detections = self.detector.analyze(correlated) if correlated else []
        flagged_dsts = {d.dst_ip for d in flood_detections}
        flagged_pairs = {(d.src_ip, d.dst_ip) for d in flood_detections}

        # Fetched once, reused for both detection input and Grafana metrics
        # below — so the "concurrent/new connections" panels show the real
        # value every cycle, not just when LOW_SLOW actually fires.
        low_volume_flow_counts = self.of_adapter.collect_low_volume_flow_counts()
        connection_port_counts = self.of_adapter.get_connection_port_counts()

        for dst_ip, count in low_volume_flow_counts.items():
            metrics.update_stalled_flows(dst_ip, count)

        for (src_ip, dst_ip), info in connection_port_counts.items():
            metrics.update_connection_counts(src_ip, dst_ip, info["count"], info["new_connections"])

        detections = list(flood_detections)
        detections += self.detector.analyze_low_slow(
            low_volume_flow_counts,
            exclude_dsts=flagged_dsts,
        )
        detections += self.detector.analyze_low_slow_single_source(
            connection_port_counts,
            exclude_pairs=flagged_pairs,
        )
        # Mobile-domain low-and-slow: many distinct UEs simultaneously
        # holding a low, sub-threshold rate toward the same destination --
        # see analyze_low_slow_mobile's docstring for why this needs its
        # own signal instead of reusing the two flow-count-based variants
        # above (OpenFlow-only telemetry).
        detections += self.detector.analyze_low_slow_mobile(
            correlated,
            exclude_dsts=flagged_dsts,
        )

        # Surface every NEW detection in the event log, classified — this
        # is the descriptive "what's happening" signal; raw traffic
        # numbers live in Grafana via /metrics instead. An attack already
        # under an active block gets re-detected every cycle for as long
        # as it's ongoing (the underlying traffic is still there), but
        # that's already being handled — skip the repeat announcement.
        for d in detections:
            if self.orchestrator.is_active_block(d.src_ip, d.dst_ip, d.dst_port, d.protocol):
                continue

            msg = (
                f"ATTACK DETECTED: {d.attack_type} "
                f"source={d.src_ip} destination={d.dst_ip}:{d.dst_port}/{d.protocol} "
                f"[{d.domain}]"
            )
            dashboard_state.add_event(msg)
            self.logger.warning(msg)

        # Mark destinations seen clean this cycle as validated — only now
        # can LearningSwitch start caching forwarding rules for them. Must
        # run even when there were no detections, so normal traffic still
        # gets validated.
        self.orchestrator.validate(correlated, detections)

        unblock_actions = openflow_unblock_actions + mobile_unblock_actions

        # Stages 4 + 5 — decide and orchestrate. A cycle can have no new
        # detections (the attack that triggered a block already stopped)
        # and still have unblocks to report, so the early return only
        # applies when there's neither.
        if not detections and not unblock_actions:
            return

        actions = self.orchestrator.process(detections) if detections else []
        actions += unblock_actions

        # Reflect mitigations in the dashboard
        for action in actions:
            msg = (
                f"MITIGATION: {action.action.upper()} ({action.attack_type}) "
                f"source={action.src_ip} destination={action.dst_ip}:{action.dst_port}/{action.protocol} "
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

        # Sample each active block's own drop-rule counters — the only
        # remaining signal of whether an attacker is still flooding a
        # blocked flow, since its packets never reach packet_in again.
        self.orchestrator.record_block_traffic(dpid, ev.msg.body)

        # Stage 1 — push raw stats into the OpenFlow telemetry adapter
        events = self.of_adapter.on_flow_stats(dpid, ev.msg.body)

        # Traffic numbers go to Prometheus/Grafana, not the console or the
        # event log — classification (Stage 3, in _run_pipeline) is what
        # gets logged as an event.
        total_bps = sum(e.bps for e in events)
        total_pps = sum(e.pps for e in events)
        metrics.update_switch_stats(dpid, total_bps, total_pps)
        dashboard_state.update_stats(dpid, total_bps, total_pps)

        # Same totals, broken down by protocol (TCP/UDP/ICMP/IP) — not by
        # physical port, since these are flow-derived events and don't
        # reliably carry in_port (LearningSwitch's L3-only match doesn't
        # either, for flow-stats-sourced ones).
        bps_by_proto: Dict[str, float] = defaultdict(float)
        pps_by_proto: Dict[str, float] = defaultdict(float)
        for e in events:
            proto = "TCP" if e.protocol == "TCP_SYN" else e.protocol
            bps_by_proto[proto] += e.bps
            pps_by_proto[proto] += e.pps
        for proto in bps_by_proto:
            metrics.update_switch_protocol_stats(
                dpid, proto, bps_by_proto[proto], pps_by_proto[proto]
            )

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
