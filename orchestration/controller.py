import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple

import config.settings as settings
from core.models import CorrelatedEvent, DetectionResult, MitigationAction
from decision.engine import DecisionEngine, Decision
from telemetry.base import DomainAdapter
from mitigation.openflow_mitigator import OpenFlowMitigator, PROTO_NUMBERS
from web import metrics


_THRESHOLD_BY_PROTOCOL = {
    "TCP": settings.SYN_THRESHOLD,
    "UDP": settings.UDP_THRESHOLD,
    "ICMP": settings.ICMP_THRESHOLD,
}


class OrchestrationController:
    """
    Orchestration and Control layer.

    Sits at the bottom of the centralized controller pipeline:
      DetectionResults → DecisionEngine → MitigationActions → Domain adapters

    Responsibilities:
    1. Run DetectionResults through the DecisionEngine to produce a Decision.
    2. Map the Decision to domain-specific MitigationActions.
    3. Dispatch each action to the correct adapter or the OpenFlowMitigator.

    The OpenFlowMitigator is kept separate from the DomainAdapter list because
    it requires live Ryu datapath references (registered/deregistered by the
    Ryu controller as switches connect and disconnect).

    Unblocking is traffic-driven rather than time-driven: a blocked flow's
    drop rule keeps counting matched (dropped) packets, so check_unblocks()
    can tell whether the attacker is still flooding and release the block
    once that flow's volume falls back under a fraction of the threshold
    that triggered it.
    """

    # Release a block once the flow's pps falls below this fraction of the
    # detection threshold that originally triggered it.
    UNBLOCK_RATIO = 0.5

    # Require this many consecutive below-threshold cycles before actually
    # unblocking, so a brief lull in a bursty attack doesn't lift the block
    # only for the next burst to need re-detection from scratch.
    UNBLOCK_CONFIRM_CYCLES = 3

    def __init__(self, adapters: List[DomainAdapter], locate_host=None, yield_fn=None):
        # Index adapters by domain name for O(1) dispatch
        self._adapters: Dict[str, DomainAdapter] = {
            a.domain_name: a for a in adapters
        }
        self._decision_engine = DecisionEngine()
        # yield_fn (e.g. ryu.lib.hub.sleep(0)) is threaded through to
        # OpenFlowMitigator so its forwarding-rule cleanup loop — which can
        # run into thousands of iterations under a distributed attack —
        # cooperatively yields instead of starving every other greenthread
        # (including each switch's own echo-reply loop) for the duration.
        self.of_mitigator = OpenFlowMitigator(yield_fn=yield_fn)

        # Optional Callable[[ip], Optional[Tuple[int,int]]] — (dpid, port)
        # an IP's mac was last confirmed attached to via a genuine edge
        # port (LearningSwitch.get_host_location). This is the actual
        # source of truth for scoping a block to the switch closest to an
        # attacker — unlike a detection's own device_id/in_port, which
        # just reflects whichever switch's packet-in happened to be
        # processed, not necessarily the one nearest the source.
        self._locate_host = locate_host

        # (src_ip, dst_ip, dst_port, protocol) -> MitigationAction currently
        # enforced, only for the openflow domain (the only one with a real
        # drop-rule backend so far).
        self._active_blocks: Dict[Tuple[str, str, int, str], MitigationAction] = {}

        # Same keys -> count of consecutive cycles seen below the unblock
        # threshold. Reset to 0 whenever traffic rises back above it.
        self._below_threshold_streak: Dict[Tuple[str, str, int, str], int] = {}

        # Destination IPs that have completed at least one full detection
        # cycle without triggering an attack. LearningSwitch refuses to
        # cache *any* rule — permit or block — for a destination until it's
        # in this set, so brand-new traffic always goes through the
        # detection pipeline before the switch commits to anything.
        self._validated_destinations: set = set()

        # (key, dpid) -> last sample of the matching drop rule's counters.
        # Once blocked, an attacker's packets are dropped in the fast path
        # and never reach packet_in again, and FlowCollector deliberately
        # excludes drop-rule entries from telemetry (so the mitigation's
        # own counters don't get re-detected as a fresh attack) — so this
        # is tracked independently, purely to answer "is this still being
        # hit" for check_unblocks.
        self._block_traffic_samples: Dict[Tuple[Tuple[str, str, int, str], int], dict] = {}

        # key -> most recently computed pps for its drop rule, summed
        # across all switches that reported a fresh-enough sample.
        self._block_pps: Dict[Tuple[str, str, int, str], float] = {}

        # (dpid, port_no) pairs known to be switch-switch links, from
        # topology discovery. A packet with no matching flow rule triggers
        # packet-in on every switch it passes through, not just the one
        # nearest the source, so an ingress (dpid, in_port) that's actually
        # one of these can't be trusted to scope a block to.
        self._interswitch_ports: set = set()

    # ------------------------------------------------------------------
    # Datapath lifecycle (called from the Ryu controller)
    # ------------------------------------------------------------------

    def register_datapath(self, datapath) -> None:
        self.of_mitigator.register(datapath)

    def update_interswitch_ports(self, ports: set) -> None:
        """Called by the Ryu controller whenever topology is (re)discovered."""
        self._interswitch_ports = ports

    def is_interswitch_port(self, dpid: int, port_no: int) -> bool:
        """Queried by LearningSwitch before trusting a mac sighting as a
        genuine host attachment point."""
        return (dpid, port_no) in self._interswitch_ports

    def deregister_datapath(self, dpid: int) -> None:
        self.of_mitigator.deregister(dpid)

    # ------------------------------------------------------------------
    # Main pipeline entry point
    # ------------------------------------------------------------------

    def process(self, detections: List[DetectionResult]) -> List[MitigationAction]:
        """
        Evaluate detections, decide on a response, and dispatch mitigation.
        Returns the list of MitigationActions that were issued (empty if no
        attack scored above the decision threshold).

        Detections are grouped by attacker identity (src_ip, dst_ip,
        dst_port, protocol) first, and each group gets its own independent
        decision/threshold check — DecisionEngine.evaluate() only ever
        returns the single best-scoring entry it's given, so without this
        grouping, two simultaneous distinct attacks (e.g. a bidirectional
        ICMP flood, or two unrelated attackers) would compete for one
        "winner" slot each cycle and only ever get mitigated one at a
        time, alternating cycle to cycle as their relative scores shift.
        """
        if not detections:
            return []

        for d in detections:
            metrics.record_detection(d.attack_type, d.domain)
            metrics.record_attack_rate(d.attack_type, d.domain, d.pps, d.bps)

        groups: Dict[Tuple[str, str, int, str], List[DetectionResult]] = defaultdict(list)
        for d in detections:
            groups[(d.src_ip, d.dst_ip, d.dst_port, d.protocol)].append(d)

        all_actions: List[MitigationAction] = []

        for group in groups.values():
            det_dicts = [
                {
                    "type": d.attack_type,
                    "src_ip": d.src_ip,
                    "score": d.score * d.confidence,
                }
                for d in group
            ]

            decision: Decision = self._decision_engine.evaluate(det_dicts)

            if decision is None:
                continue

            actions = self._build_actions(decision, group)

            for action in actions:
                if self._dispatch(action):
                    # Only newly-enforced actions are reported back — an
                    # already-active block re-dispatching every cycle
                    # (because the attack is still ongoing) is a no-op at
                    # the mitigator level, so it shouldn't re-log either.
                    all_actions.append(action)

        return all_actions

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_actions(
        self,
        decision: Decision,
        detections: List[DetectionResult],
    ) -> List[MitigationAction]:
        """
        Build one MitigationAction per affected domain.
        Chooses the mitigation action type based on attack type and domain.
        """
        actions: List[MitigationAction] = []
        seen_domains = set()

        for d in detections:

            if d.domain in seen_domains:
                continue

            seen_domains.add(d.domain)

            action_type = self._action_for(decision.attack_type, d.domain)

            device_id, in_port = self._scoped_ingress(d)

            actions.append(MitigationAction(
                domain=d.domain,
                device_id=device_id,
                src_ip=decision.src_ip,
                dst_ip=d.dst_ip,
                dst_port=d.dst_port,
                protocol=d.protocol,
                action=action_type,
                sources=d.sources,
                attack_type=decision.attack_type,
                in_port=in_port,
                pps=d.pps,
                bps=d.bps,
            ))

        return actions

    def _scoped_ingress(self, d: DetectionResult) -> Tuple[str, int]:
        """
        Find the switch+port actually closest to this detection's src_ip,
        via LearningSwitch's confirmed host-location tracking (mac
        sightings filtered to genuine edge ports, never an inter-switch
        hop's view of the same mac) — NOT the detection's own
        device_id/in_port, which just reflects whichever switch's
        packet-in happened to get processed for that traffic. A packet
        with no matching flow rule triggers packet-in on every switch it
        passes through, not just the one nearest the actual source, so
        that telemetry-derived info isn't reliable enough to scope a
        block to a single switch+port — only an authoritative location
        lookup is. No location known yet -> fall back to network-wide.
        """
        if self._locate_host is None:
            return "", 0

        location = self._locate_host(d.src_ip)

        if location is None:
            return "", 0

        dpid, port_no = location
        return str(dpid), port_no

    @staticmethod
    def _action_for(attack_type: str, domain: str) -> str:
        """Map attack type + domain to a concrete mitigation action string."""
        if domain == "bgp":
            return "bgp_blackhole"
        if attack_type in ("SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "DDOS_DISTRIBUTED", "LOW_SLOW"):
            return "block"
        return "rate_limit"

    def _dispatch(self, action: MitigationAction) -> bool:
        """
        Send action to the correct backend. Returns True if this is a
        newly-enforced action worth reporting (logging) — False if it's
        just process() re-evaluating an attack that's already blocked,
        which would otherwise re-log every cycle for as long as the
        attack stays active.
        """
        metrics.record_mitigation(action.attack_type, action.action, action.domain)
        metrics.record_mitigation_rate(action.attack_type, action.action, action.pps, action.bps)

        if action.domain == "openflow":
            is_new = True

            if action.action == "block":
                key = (action.src_ip, action.dst_ip, action.dst_port, action.protocol)
                is_new = key not in self._active_blocks
                self._active_blocks[key] = action
                self._below_threshold_streak[key] = 0
                metrics.set_active_blocks(len(self._active_blocks))

                if is_new:
                    # Counted per distinct block event, not per cycle an
                    # already-active one gets re-evaluated — see is_new
                    # above and the docstring.
                    metrics.record_block_endpoints(action.src_ip, action.dst_ip)

            # Install the actual protective rule FIRST — a distributed
            # attack can have hundreds/thousands of spoofed sources, and
            # clear_forwarding_rules() below sends one OFPFlowMod per
            # source per switch synchronously; with enough sources that
            # can take long enough to noticeably delay the real
            # mitigation if it ran first. The drop rule already outranks
            # any per-source forwarding rule by priority regardless of
            # whether those get cleaned up, so nothing depends on cleanup
            # happening before the block is live.
            self.of_mitigator.apply(action)

            if action.action == "block" and action.src_ip == "*" and action.sources:
                self.of_mitigator.clear_forwarding_rules(action.dst_ip, action.sources)

            return is_new

        adapter = self._adapters.get(action.domain)

        if adapter:
            adapter.apply_mitigation(action)
        else:
            print(
                f"{datetime.now():%Y-%m-%d %H:%M:%S} "
                f"[ORCHESTRATION] No adapter registered "
                f"for domain '{action.domain}'"
            )

        return True

    # ------------------------------------------------------------------
    # Queried by the forwarding layer before caching a new flow
    # ------------------------------------------------------------------

    def is_blocked_destination(self, dst_ip: str, dst_port: int, protocol: str) -> bool:
        """
        True if there's an active destination-wide ("*" src) block covering
        this exact (dst_ip, dst_port, protocol). LearningSwitch checks this
        before installing a new per-source forwarding rule, so once a
        distributed attack's destination is blocked, new spoofed sources
        stop generating pointless one-shot forwarding entries — the drop
        rule would win on priority anyway, but there's no reason to let the
        flow table fill up with entries that can never deliver traffic.
        """
        return ("*", dst_ip, dst_port, protocol) in self._active_blocks

    def is_active_block(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> bool:
        """
        True if this exact (src_ip, dst_ip, dst_port, protocol) already
        has an active block. Used to skip re-logging "ATAQUE DETECTADO"
        every cycle for an attack that's already known and being handled.
        """
        return (src_ip, dst_ip, dst_port, protocol) in self._active_blocks

    def is_validated_destination(self, dst_ip: str) -> bool:
        """
        True once dst_ip has completed at least one full detection cycle
        without being flagged as an attack. LearningSwitch checks this
        before installing *any* flow rule for a destination — permit or
        block — so brand-new traffic is always forwarded packet-by-packet
        (no caching either way) until the pipeline has actually evaluated
        it at least once.
        """
        return dst_ip in self._validated_destinations

    def validate(self, correlated: List[CorrelatedEvent], detections: List[DetectionResult]) -> None:
        """
        Called once per pipeline cycle, after detection. Any destination
        that was observed this cycle and did NOT trigger a detection has
        now been evaluated and found clean — mark it validated so
        LearningSwitch can start caching forwarding rules for it. A
        destination that did trigger a detection is left unvalidated; it
        gets blocked instead, and stays unvalidated until traffic toward
        it is reassessed clean in some future cycle.
        """
        flagged_dsts = {d.dst_ip for d in detections}

        for c in correlated:
            if c.dst_ip not in flagged_dsts:
                self._validated_destinations.add(c.dst_ip)

    # ------------------------------------------------------------------
    # Continuous sweep — catches forwarding rules clear_forwarding_rules()
    # missed at block time
    # ------------------------------------------------------------------

    def sweep_blocked_forwarding(self, body) -> None:
        """
        Delete any L3 forwarding rule (priority=FORWARDING_PRIORITY) whose
        destination is currently under an active "*" (distributed) block.

        clear_forwarding_rules() at block time only knows the sources the
        detection had already seen by then. Sources that slip in during the
        race window between the attack starting and the block actually
        taking effect — especially one-shot spoofed sources that never get
        a second flow-stats sample — never make it into that list and
        would otherwise sit in the flow table forever (harmless, since the
        drop rule outranks them, but exactly the clutter we want gone).

        Called every flow_stats_reply cycle with the raw OFPFlowStatsReply
        body for one switch, so it sees the table as OVS actually has it,
        not just what detection inferred.
        """
        blocked_dsts = {
            dst_ip for (src_ip, dst_ip, _, _) in self._active_blocks if src_ip == "*"
        }

        if not blocked_dsts:
            return

        stale_sources_by_dst: Dict[str, List[str]] = defaultdict(list)

        for stat in body:
            if stat.priority != self.of_mitigator.FORWARDING_PRIORITY:
                continue

            match = stat.match

            if match.get("eth_type") != 0x0800:
                continue

            dst_ip = match.get("ipv4_dst")
            src_ip = match.get("ipv4_src")

            if dst_ip in blocked_dsts and src_ip:
                stale_sources_by_dst[dst_ip].append(src_ip)

        for dst_ip, sources in stale_sources_by_dst.items():
            self.of_mitigator.clear_forwarding_rules(dst_ip, sources)

    # ------------------------------------------------------------------
    # Continuous measurement of each block's own drop-rule traffic
    # ------------------------------------------------------------------

    def record_block_traffic(self, dpid: int, body) -> None:
        """
        Sample the packet/byte counters of each active block's drop rule
        on this switch and turn the delta since the last sample into a
        pps figure check_unblocks() can use. Called every flow_stats_reply
        cycle, same as sweep_blocked_forwarding().
        """
        if not self._active_blocks:
            return

        now = time.time()

        for stat in body:
            if stat.priority != self.of_mitigator.DROP_PRIORITY:
                continue

            match = stat.match

            for key in self._active_blocks:
                if not self._stat_matches_block(match, key):
                    continue

                sample_key = (key, dpid)
                prev = self._block_traffic_samples.get(sample_key)

                self._block_traffic_samples[sample_key] = {
                    "bytes": stat.byte_count,
                    "packets": stat.packet_count,
                    "time": now,
                }

                if prev is None:
                    break

                dt = now - prev["time"]

                if dt < settings.MIN_FLOW_RATE_DT:
                    break

                packet_delta = stat.packet_count - prev["packets"]

                if packet_delta < 0:
                    break

                self._block_pps[key] = packet_delta / dt
                break

    @staticmethod
    def _stat_matches_block(match, key) -> bool:
        src_ip, dst_ip, dst_port, protocol = key

        if match.get("eth_type") != 0x0800:
            return False
        if match.get("ipv4_dst") != dst_ip:
            return False

        match_src = match.get("ipv4_src")
        if src_ip == "*":
            if match_src:
                return False  # this is some other, source-specific rule
        elif match_src != src_ip:
            return False

        if match.get("ip_proto") != PROTO_NUMBERS.get(protocol):
            return False

        if protocol == "TCP" and match.get("tcp_dst", 0) != dst_port:
            return False
        if protocol == "UDP" and match.get("udp_dst", 0) != dst_port:
            return False

        return True

    def _forget_block_traffic(self, key) -> None:
        self._block_pps.pop(key, None)
        for sample_key in [k for k in self._block_traffic_samples if k[0] == key]:
            del self._block_traffic_samples[sample_key]

    # ------------------------------------------------------------------
    # Unblocking — driven by the current volume of each blocked flow
    # ------------------------------------------------------------------

    def check_unblocks(self) -> None:
        """
        Re-evaluate every active openflow block. A block is released once
        its drop rule's own pps (see record_block_traffic — telemetry from
        the regular pipeline goes silent for a blocked flow, since its
        packets never reach packet_in again and FlowCollector excludes
        drop-rule entries) has stayed below UNBLOCK_RATIO of the
        triggering threshold for UNBLOCK_CONFIRM_CYCLES consecutive
        cycles — i.e. once the controller no longer "feels" the attack,
        confirmed rather than on a single quiet sample.
        """
        if not self._active_blocks:
            return

        for key in list(self._active_blocks):
            src_ip, dst_ip, dst_port, protocol = key

            pps = self._block_pps.get(key, 0.0)

            if src_ip == "*":
                threshold = settings.DIST_PPS_THRESHOLD
            else:
                threshold = _THRESHOLD_BY_PROTOCOL.get(protocol, settings.UDP_THRESHOLD)

            if pps >= threshold * self.UNBLOCK_RATIO:
                self._below_threshold_streak[key] = 0
                continue

            self._below_threshold_streak[key] += 1

            if self._below_threshold_streak[key] >= self.UNBLOCK_CONFIRM_CYCLES:
                self.of_mitigator.unblock(src_ip, dst_ip, dst_port, protocol)
                del self._active_blocks[key]
                del self._below_threshold_streak[key]
                self._forget_block_traffic(key)
                metrics.set_active_blocks(len(self._active_blocks))
                # Force re-validation: a destination that was just under
                # attack shouldn't get its forwarding rules trusted again
                # without going through at least one more clean cycle.
                self._validated_destinations.discard(dst_ip)
