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
from core.log_format import log_line

# Display verb for the MITIGATION log line, by domain -- the mobile
# domain doesn't block anything on a network path the way an OpenFlow
# drop rule does; MobileNetworkAdapter.apply_mitigation() queues a RAN-
# side throttle (UE quarantined to a near-zero-PRB slice) instead, so
# logging it as "BLOCK"/"UNBLOCK" describes a mechanism this domain
# doesn't actually have. Domains not listed here (openflow, bgp, ...)
# fall back to the action string itself.
_MITIGATION_VERBS = {
    "mobile": {"block": "THROTTLE", "unblock": "UNTHROTTLE"},
}


def _format_mitigation_message(action) -> str:
    """
    OpenFlow's drop rule genuinely is scoped to one flow (src/dst/port/
    protocol), so "source=X destination=Y:Z/W" accurately describes what
    got blocked. The mobile throttle doesn't work that way: it quarantines
    the UE's entire radio link regardless of what it's talking to, so the
    destination it was attacking is irrelevant to *performing* the
    throttle -- it's just what triggered the decision, already reported
    by the ATTACK DETECTED line a few lines up. What an E2SM-RC slice-
    association control actually needs to locate and quarantine the UE
    is its identity and which gNB/E2 node it's attached to (see Option 1
    in the FlexRIC investigation: control_sm_xapp_api() takes a UE id and
    E2 node id, not a destination), plus how long the quarantine should
    last -- so that's what this message reports instead.
    """
    verb = _MITIGATION_VERBS.get(action.domain, {}).get(action.action, action.action.upper())

    if action.domain == "mobile":
        gnb = action.device_id or "unknown"
        # duration only means something for the throttle itself -- the
        # unblock/release action never sets it, so it'd otherwise just
        # leak MitigationAction's dataclass default (60) on every
        # UNTHROTTLE line regardless of how long the real one ran.
        duration_part = f" duration={action.duration}s" if action.action == "block" else ""
        return log_line(
            "mobile", "MITIGATION", verb,
            f"{action.attack_type} UE src_ip={action.src_ip} gNB={gnb}{duration_part}",
        )

    return log_line(
        action.domain, "MITIGATION", verb,
        f"{action.attack_type} source={action.src_ip} "
        f"destination={action.dst_ip}:{action.dst_port}/{action.protocol}",
    )


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

        # MobileNetworkAdapter and BroadbandAdapter are real now (real
        # E2/KPM pipeline via simulation/parse_xapp_kpm_log.py's CSV for
        # mobile, real BNGBlaster pipeline via simulation/
        # bng_traffic_simulator.py's CSV + control socket for broadband
        # -- see each module's docstring). of_adapter IS the Enterprise
        # domain (OpenFlow/SDN over the PE-facing topology) -- there is
        # no separate Enterprise adapter/stub; External Peering (BGP)
        # remains a stub.
        self.all_adapters = [
            self.of_adapter,
            MobileNetworkAdapter(logger=self.logger),
            BroadbandAdapter(bng_host="bng-blaster-1"),
            BGPPeeringAdapter(),         # stub — wire up router_host later (External Peering domain)
        ]

        # Domains that had at least one active mitigation block as of the
        # last cycle -- see _run_pipeline's metrics.set_active_blocks_by_domain
        # call for why this is needed (a domain dropping to zero blocks
        # needs an explicit 0 sent, or its Grafana gauge just keeps
        # showing the last nonzero value forever).
        self._known_active_block_domains = set()

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

        self.logger.info(log_line("controller", "STARTUP", "READY"))

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
            self.logger.error(log_line("controller", "TOPOLOGY", "ERROR", str(e)))

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        dashboard_state.add_event("Switch added to topology")
        self._update_topology()

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        dashboard_state.add_event("Switch removed from topology")
        # Forgets this dpid's OpenFlowMitigator datapath -- without this,
        # a disconnected switch's entry lingered forever, and a future
        # block decided to target it (e.g. reusing the same dpid after a
        # Mininet restart) could resolve to a stale, no-longer-valid
        # datapath handle.
        self.orchestrator.deregister_datapath(ev.switch.dp.id)
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

        self.logger.info(log_line("enterprise", "FORWARDING", "SWITCH_CONNECTED", f"id={datapath.id}"))

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
                    self.logger.error(log_line("enterprise", "TELEMETRY", "ERROR", str(e)))

            hub.sleep(settings.COLLECT_INTERVAL)

            # Refresh hosts on the topology graph — switch/link events
            # alone wouldn't pick up a newly-learned host location.
            self._update_topology()

            # Run the full 5-stage pipeline. Wrapped -- confirmed on a
            # real run that an uncaught exception here silently kills
            # this entire hub greenthread: the process stays up (other
            # ryu apps/handlers keep responding), ryu-manager prints
            # nothing visible, and _monitor's while loop simply never
            # iterates again -- no more telemetry collection, detection,
            # or mitigation for any domain, indefinitely, with zero
            # indication anything went wrong. Logged with a full
            # traceback now instead of vanishing.
            try:
                self._run_pipeline()
            except Exception:
                self.logger.exception(log_line("controller", "PIPELINE", "ERROR"))

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
                self.logger.error(log_line(adapter.domain_name, "TELEMETRY", "ERROR", str(e)))

        # Per-domain traffic KPI for Grafana -- every domain's collect()
        # output, aggregated regardless of whether anything crosses a
        # detection threshold this cycle, so each domain's dashboard has
        # a baseline "is telemetry even flowing" panel instead of only
        # ever showing attack-triggered spikes. Computed for every
        # adapter (even ones that returned nothing this cycle) so a
        # domain that goes quiet correctly drops to 0 instead of its
        # gauge keeping its last nonzero value forever.
        events_by_domain = defaultdict(list)
        for e in all_events:
            events_by_domain[e.domain].append(e)
        for adapter in self.all_adapters:
            domain_events = events_by_domain.get(adapter.domain_name, [])
            metrics.update_domain_traffic(
                adapter.domain_name,
                pps=sum(e.pps for e in domain_events),
                bps=sum(e.bps for e in domain_events),
                active_sources=len({e.src_ip for e in domain_events}),
            )

        # Same zero-fill concern for "active blocks by domain" -- a
        # domain whose last block just got released needs an explicit 0
        # sent this cycle, not just silently dropping out of the dict
        # active_block_counts_by_domain() returns.
        block_counts = self.orchestrator.active_block_counts_by_domain()
        domains_to_zero = self._known_active_block_domains - block_counts.keys()
        metrics.set_active_blocks_by_domain({**{d: 0 for d in domains_to_zero}, **block_counts})
        self._known_active_block_domains = set(block_counts.keys())

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

        # Stage 3 — detect attack types.
        detections = self.detector.analyze(correlated) if correlated else []

        # Drop detections for a (src, dst, port, protocol) already under
        # an active block BEFORE they reach metrics/validate/process.
        detections = [
            d for d in detections
            if not self.orchestrator.is_active_block(d.src_ip, d.dst_ip, d.dst_port, d.protocol, sources=d.sources)
        ]

        # Surface every NEW detection in the event log, classified — this
        # is the descriptive "what's happening" signal; raw traffic
        # numbers live in Grafana via /metrics instead.
        for d in detections:

            msg = log_line(
                d.domain, "DETECTION", "ATTACK_DETECTED",
                f"{d.attack_type} source={d.src_ip} destination={d.dst_ip}:{d.dst_port}/{d.protocol}",
            )
            dashboard_state.add_event(msg)
            self.logger.warning(msg)

            # Dashboard's "attacks" panel (web/api.py, web/socket_server.py,
            # templates/index.html all read dashboard_state.attacks) is
            # switch-rate-shaped (dpid/byte_rate/packet_rate) -- only
            # OpenFlow-domain detections have a real dpid (d.device_id) to
            # report it under; a mobile-domain UE has no switch to attribute
            # the rate to.
            if d.domain == "enterprise" and d.device_id.isdigit():
                dashboard_state.add_attack(int(d.device_id), d.bps, d.pps)

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
            msg = _format_mitigation_message(action)
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
