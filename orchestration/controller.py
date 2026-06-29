import logging
import time
from collections import defaultdict
from typing import Dict, List, Set, Tuple

import config.settings as settings
from core.log_format import log_line
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
    # only for the next burst to need re-detection from scratch. Shared by
    # both check_unblocks() (openflow) and check_mobile_unblocks() (mobile).
    # Expressed in pipeline CYCLES, not real time -- this implicitly meant
    # 50s of confirmation back when config.settings.COLLECT_INTERVAL was
    # 5s. Once COLLECT_INTERVAL got lowered to 0.5s (for mobile-domain
    # sub-second latency), the same 10-cycle count silently became only 5s
    # of real confirmation -- confirmed on a real run: openflow would
    # BLOCK a still-running hping3 SYN flood and then UNBLOCK it ~5s later
    # because a couple of noisy below-threshold samples off the DROP
    # rule's own counters (record_block_traffic) were enough to satisfy
    # 10 cycles, triggering a fast BLOCK/UNBLOCK/re-detect oscillation.
    # Raised 10x to restore the original 50s of real confirmation time.
    UNBLOCK_CONFIRM_CYCLES = 100

    def __init__(
        self, adapters: List[DomainAdapter], locate_host=None,
        locate_source_ingress=None, yield_fn=None, logger=None,
    ):
        # Index adapters by domain name for O(1) dispatch
        self._adapters: Dict[str, DomainAdapter] = {
            a.domain_name: a for a in adapters
        }
        self._decision_engine = DecisionEngine()
        # Passed down from the Ryu app (its own self.logger) so every log
        # line across domains shares the same name/format -- defaults to
        # a plain logging.Logger so this stays usable standalone (tests,
        # no Ryu runtime).
        self._logger = logger or logging.getLogger(__name__)
        # yield_fn (e.g. ryu.lib.hub.sleep(0)) is threaded through to
        # OpenFlowMitigator so its forwarding-rule cleanup loop — which can
        # run into thousands of iterations under a distributed attack —
        # cooperatively yields instead of starving every other greenthread
        # (including each switch's own echo-reply loop) for the duration.
        self.of_mitigator = OpenFlowMitigator(yield_fn=yield_fn, logger=self._logger)

        # Optional Callable[[ip], Optional[Tuple[int,int]]] — (dpid, port)
        # an IP's mac was last confirmed attached to via a genuine edge
        # port (LearningSwitch.get_host_location). This is the actual
        # source of truth for scoping a block to the switch closest to an
        # attacker — unlike a detection's own device_id/in_port, which
        # just reflects whichever switch's packet-in happened to be
        # processed, not necessarily the one nearest the source.
        self._locate_host = locate_host

        # Optional Callable[[src_ip, dst_ip], Tuple[Optional[int],
        # Optional[int]]] — (dpid, in_port) a (src_ip, dst_ip) pair was
        # last observed entering on via packet-in (OpenFlowAdapter.
        # get_source_ingress). Unlike _locate_host above, this works for
        # a spoofed/fabricated src_ip too — it reflects where the packet
        # physically arrived, not an ARP-learned identity a fake IP could
        # never produce. Used to scope each individual source's block in
        # a distributed attack to its own real ingress switch+port.
        self._locate_source_ingress = locate_source_ingress

        # (src_ip, dst_ip, dst_port, protocol) -> MitigationAction currently
        # enforced for the mobile domain (separate from _active_blocks
        # below because its unblock signal is telemetry-pps-based, not
        # openflow drop-rule-counter-based -- see check_mobile_unblocks).
        self._active_mobile_blocks: Dict[Tuple[str, str, int, str], MitigationAction] = {}
        self._mobile_below_threshold_streak: Dict[Tuple[str, str, int, str], int] = {}
        # (src_ip, dst_ip, dst_port, protocol) -> time.time() the block was
        # first dispatched -- only consulted for domains in
        # settings.PRESENCE_BLIND_DOMAINS (see check_mobile_unblocks's
        # docstring on why those can't use the presence-streak signal at
        # all: a real session-stop suppresses every TelemetryEvent for
        # that source, which is indistinguishable from "the attacker
        # stopped" if presence is the only signal available).
        self._mobile_block_started_at: Dict[Tuple[str, str, int, str], float] = {}

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

            newly_enforced: List[MitigationAction] = []

            for action in actions:
                if self._dispatch(action):
                    # Only newly-enforced actions are reported back — an
                    # already-active block re-dispatching every cycle
                    # (because the attack is still ongoing) is a no-op at
                    # the mitigator level, so it shouldn't re-log either.
                    newly_enforced.append(action)
                    all_actions.append(action)

            if (
                newly_enforced
                and decision.attack_type == "DDOS_DISTRIBUTED"
                and newly_enforced[0].domain == "enterprise"
            ):
                # One cleanup pass per group, after every location's block
                # in it is already live — not per action, since
                # _build_actions can split one distributed detection into
                # several actions (one per distinct ingress location),
                # each carrying only the sources seen at ITS location; the
                # union covers every source in the whole detection.
                all_sources = {s for action in newly_enforced for s in action.sources}
                if all_sources:
                    self.of_mitigator.clear_forwarding_rules(
                        newly_enforced[0].dst_ip, list(all_sources)
                    )

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

        DDOS_DISTRIBUTED on the openflow domain is the one exception:
        instead of one destination-wide action with no location at all,
        every source IP the detection saw is first resolved to the
        physical HOST port its packets were actually confirmed entering
        on (see _scoped_ingress_for_source — packet-in-derived and
        host-port-filtered, works even for a spoofed src_ip, since it
        reflects where the packet arrived, not an ARP-learned identity a
        fake IP could never produce), then grouped by that location. One
        action per *distinct location* is built — not per source —
        matching only (in_port, dst_ip, dst_port, protocol), no src_ip:
        a real spoofed flood is virtually always many fake IPs funneled
        through ONE real attacker port, so this normally collapses to a
        single precise block instead of one rule per fake IP.

        Sources with no confirmed host-port location yet are skipped
        entirely — NEVER blocked network-wide; they'll get caught once a
        host-port sighting for them arrives in a later cycle. OpenFlow's
        own LOW_SLOW flow-count variant also uses src_ip="*" but carries
        no per-source IP list at all (it's a flow-count signature, not a
        list of attackers), so it's left as a single network-wide action
        via the normal path below — that one has no per-source location
        to scope to in the first place, unlike DDOS_DISTRIBUTED.

        Mobile-domain LOW_SLOW and DDOS_DISTRIBUTED are the analogous
        exception for that domain (see the branch below) — both carry a
        real per-source UE list, and mobile mitigation has no network-
        wide lever at all, so each contributing UE gets its own action
        instead of one with an unresolvable src_ip="*".
        """
        actions: List[MitigationAction] = []
        seen_domains = set()

        for d in detections:

            if d.domain in seen_domains:
                continue

            seen_domains.add(d.domain)

            action_type = self._action_for(decision.attack_type, d.domain)

            if d.domain == "enterprise" and decision.attack_type == "DDOS_DISTRIBUTED" and d.sources:
                by_location: Dict[Tuple[str, int], List[str]] = defaultdict(list)
                for source in d.sources:
                    device_id, in_port = self._scoped_ingress_for_source(source, d.dst_ip)
                    if not device_id:
                        # No confirmed host-port sighting for this source
                        # yet — skip it rather than fall back to a
                        # network-wide block.
                        continue
                    by_location[(device_id, in_port)].append(source)

                for (device_id, in_port), sources_at_location in by_location.items():
                    actions.append(MitigationAction(
                        domain=d.domain,
                        device_id=device_id,
                        src_ip="*",
                        dst_ip=d.dst_ip,
                        dst_port=d.dst_port,
                        protocol=d.protocol,
                        action=action_type,
                        sources=sources_at_location,
                        attack_type=decision.attack_type,
                        in_port=in_port,
                        pps=d.pps,
                        bps=d.bps,
                    ))
                continue

            if (
                d.domain in settings.PER_SOURCE_MITIGATION_DOMAINS
                and decision.attack_type in ("LOW_SLOW", "DDOS_DISTRIBUTED")
                and d.sources
            ):
                # Mirrors the openflow DDOS_DISTRIBUTED branch above, but
                # simpler: domains in PER_SOURCE_MITIGATION_DOMAINS (mobile
                # UEs, BNGBlaster subscriber sessions) have inherently
                # per-source mitigation -- there's no destination-wide
                # network lever the way an OpenFlow drop rule is -- so a
                # "*" src_ip can't be dispatched as a single action the
                # way it can for OpenFlow. Covers both multi-source attack
                # types LOW_SLOW and DDOS_DISTRIBUTED -- both carry their
                # contributing sources in `sources` and both would
                # otherwise build a MitigationAction with src_ip="*",
                # which the domain adapter can never resolve to a real
                # IMSI/session-id (logs "Cannot resolve src_ip * ...",
                # mitigates nothing) and which check_mobile_unblocks can
                # never confirm "still present" either -- no real
                # TelemetryEvent ever has src_ip=="*" literally, so that
                # bogus block would unblock itself again after exactly
                # UNBLOCK_CONFIRM_CYCLES regardless of whether the attack
                # was still ongoing (observed: a real distributed attack
                # being detected once, "blocked" as a no-op, automatically
                # "unblocked" a few seconds later, and the same traffic
                # then re-surfacing as several individual SYN_FLOOD
                # detections instead). One action per contributing source
                # instead, each quarantined individually through the
                # existing per-source block/unblock machinery, which
                # already works correctly per real source IP.
                for source in d.sources:
                    actions.append(MitigationAction(
                        domain=d.domain,
                        # This UE's OWN gNB (DetectionResult.source_device_ids),
                        # not d.device_id (just one representative
                        # contributing event's gNB) -- contributing UEs can
                        # each be attached to a different simulated gNB
                        # (see ul_traffic_simulator.py's --gnb-count), so
                        # using d.device_id for all of them mislabeled
                        # every UE except the representative's with the
                        # wrong gNB. Falls back to d.device_id only if a
                        # source is somehow missing from the map (shouldn't
                        # happen -- every source in d.sources came from the
                        # same event.events this map was built from).
                        device_id=d.source_device_ids.get(source, d.device_id),
                        src_ip=source,
                        dst_ip=d.dst_ip,
                        dst_port=d.dst_port,
                        protocol=d.protocol,
                        action=action_type,
                        attack_type=decision.attack_type,
                        pps=d.pps,
                        bps=d.bps,
                    ))
                continue

            if d.domain in settings.PER_SOURCE_MITIGATION_DOMAINS:
                # _scoped_ingress below resolves an OpenFlow switch+port
                # via LearningSwitch's host-location tracking -- not
                # applicable here (neither a mobile UE nor a BNGBlaster
                # subscriber session has an OpenFlow ingress port concept).
                # d.device_id is already the real gNB/BNG id for this
                # source (see the per-UE/per-session branch above), which
                # IS what the RIC/BNG control plane would need to locate it.
                device_id, in_port = d.device_id, 0
            else:
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

    def _scoped_ingress_for_source(self, src_ip: str, dst_ip: str) -> Tuple[str, int]:
        """
        Like _scoped_ingress, but for one source IP inside a distributed
        attack — uses the packet-in-observed ingress (OpenFlowAdapter.
        get_source_ingress), not ARP-based host location, since a
        spoofed src_ip never ARPs and would never resolve there. Falls
        back to network-wide for that one source if its ingress was
        never captured (e.g. only ever seen via flow-stats aggregation,
        never its own packet-in).
        """
        if self._locate_source_ingress is None:
            return "", 0

        dpid, port_no = self._locate_source_ingress(src_ip, dst_ip)

        if dpid is None:
            return "", 0

        return str(dpid), port_no or 0

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
        metrics.record_mitigation_rate(action.attack_type, action.action, action.domain, action.pps, action.bps)

        if action.domain == "enterprise":
            is_new = True

            if action.action == "block":
                key = (action.src_ip, action.dst_ip, action.dst_port, action.protocol)
                is_new = key not in self._active_blocks

                if is_new:
                    # Only set on first block, not every re-evaluation --
                    # the same flow can flip between classifications cycle
                    # to cycle right at the edge of a threshold/entropy
                    # boundary (e.g. LOW_SLOW one cycle, SYN_FLOOD the
                    # next, for the literal same attack -- see
                    # DDoSDetectionEngine's grace-period comments for why
                    # this race exists). Overwriting _active_blocks[key]
                    # on every re-evaluation made the eventual UNBLOCK
                    # line report whichever attack_type happened to be
                    # classified LAST, not the one that was actually
                    # logged as the block -- confusing when they differ.
                    self._active_blocks[key] = action
                    self._below_threshold_streak[key] = 0
                    metrics.set_active_blocks(len(self._active_blocks))
                    # Counted per distinct block event, not per cycle an
                    # already-active one gets re-evaluated — see is_new
                    # above and the docstring.
                    metrics.record_block_endpoints(action.src_ip, action.dst_ip)

            # Install the actual protective rule — cleanup of any stray
            # forwarding/permit rules for this group happens once, after
            # every action in the group is live (see process()), not
            # here: a distributed attack explodes into one action per
            # source, all sharing the same dst_ip/sources list, so
            # cleaning up per-action would redundantly re-scan the flow
            # table once per source instead of once per attack.
            self.of_mitigator.apply(action)

            return is_new

        if action.domain in settings.PER_SOURCE_MITIGATION_DOMAINS and action.action == "block":
            # Mirrors the openflow branch above: dedupe so an attack
            # that's still ongoing doesn't re-queue a fresh mitigation
            # command (and re-log "MITIGATION") every single pipeline
            # cycle — check_mobile_unblocks() is what eventually clears
            # this once the source's reported throughput actually drops.
            # Shared by every PER_SOURCE_MITIGATION_DOMAINS member (mobile
            # UEs, BNGBlaster sessions) -- the dict key carries no domain
            # field, just (src_ip, dst_ip, dst_port, protocol), which is
            # already unambiguous since a given src_ip belongs to exactly
            # one domain in practice.
            key = (action.src_ip, action.dst_ip, action.dst_port, action.protocol)
            is_new = key not in self._active_mobile_blocks

            if not is_new:
                return False

            # Only set on first throttle, not every re-evaluation -- see
            # the matching comment in the openflow branch above for why
            # (a flow can flip classification cycle to cycle right at a
            # threshold/entropy boundary; overwriting here would make the
            # eventual UNTHROTTLE line report the wrong attack_type).
            self._active_mobile_blocks[key] = action
            self._mobile_below_threshold_streak[key] = 0
            self._mobile_block_started_at[key] = time.time()

            adapter = self._adapters.get(action.domain)
            if adapter:
                adapter.apply_mitigation(action)
            return True

        adapter = self._adapters.get(action.domain)

        if adapter:
            adapter.apply_mitigation(action)
        else:
            self._logger.error(log_line(action.domain, "ORCHESTRATION", "ADAPTER_MISSING"))

        return True

    def active_block_counts_by_domain(self) -> Dict[str, int]:
        """For web/metrics.py's ddos_active_blocks_by_domain (per-domain
        Grafana dashboards' "active blocks" panel) -- both _active_blocks
        (openflow's own dict) and _active_mobile_blocks (shared by every
        config.settings.PER_SOURCE_MITIGATION_DOMAINS member) store
        MitigationActions that carry their own .domain, so this just
        groups by that instead of needing a separate counter per domain
        threaded through every block/unblock call site.

        Only includes domains with at least one block active RIGHT NOW
        -- a domain that just dropped to zero won't have a key here at
        all. The caller is responsible for explicitly zeroing a domain's
        gauge once it disappears from this dict (a missing Prometheus
        label keeps showing its last value forever, it doesn't reset).
        """
        counts: Dict[str, int] = defaultdict(int)
        for action in self._active_blocks.values():
            counts[action.domain] += 1
        for action in self._active_mobile_blocks.values():
            counts[action.domain] += 1
        return dict(counts)

    # ------------------------------------------------------------------
    # Queried by the forwarding layer before caching a new flow
    # ------------------------------------------------------------------

    def is_blocked(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> bool:
        """
        True if this exact (src_ip, dst_ip, dst_port, protocol) is
        blocked, or a "*" (destination/location-wide) block covers
        (dst_ip, dst_port, protocol) — DDOS_DISTRIBUTED blocks are
        always keyed by src_ip="*" (scoped by physical ingress
        switch+port instead, not by which fake IP a packet claims to be
        from) and LOW_SLOW's flow-count variant has no source at all, so
        both rely on this fallback. LearningSwitch checks this before
        installing a new per-source forwarding rule, so a flow already
        covered by an active block doesn't get a pointless one-shot
        permit entry — the drop rule would win on priority anyway, but
        there's no reason to let the flow table fill up with entries
        that can never deliver traffic.
        """
        if (src_ip, dst_ip, dst_port, protocol) in self._active_blocks:
            return True
        return ("*", dst_ip, dst_port, protocol) in self._active_blocks

    def is_active_block(
        self, src_ip: str, dst_ip: str, dst_port: int, protocol: str,
        sources: "list[str] | None" = None,
    ) -> bool:
        """
        True if this exact (src_ip, dst_ip, dst_port, protocol) already
        has an active block. Used to skip re-logging "ATTACK DETECTED"
        every cycle for an attack that's already known and being
        handled — DDOS_DISTRIBUTED on the openflow domain always carries
        src_ip="*", which directly matches the literal key stored for it
        (one entry per distinct physical ingress location; see
        _build_actions). Also true for an active mobile-domain block
        (_active_mobile_blocks) — same dedup purpose, separate dict
        because its unblock signal is telemetry-presence-based rather
        than openflow drop-rule-counter-based.

        sources: the detection's own per-source UE list, when it has one
        (DetectionResult.sources, populated for mobile-domain LOW_SLOW/
        DDOS_DISTRIBUTED). Those are dispatched as one action per real
        UE IP, not one action keyed by the literal "*" (see _build_
        actions's mobile branch) -- src_ip="*" alone would never match
        any of those per-UE keys, so every still-active multi-source
        mobile attack would otherwise re-log "ATTACK DETECTED" every
        single cycle even while already correctly blocked. Checking any
        one contributing UE's key is enough: they're all dispatched
        together and torn down together.
        """
        key = (src_ip, dst_ip, dst_port, protocol)
        if key in self._active_blocks or key in self._active_mobile_blocks:
            return True
        if sources:
            return any(
                (source, dst_ip, dst_port, protocol) in self._active_mobile_blocks
                for source in sources
            )
        return False

    def active_block_pairs_and_dsts(self) -> Tuple[Set[Tuple[str, str]], Set[str]]:
        """
        (src_ip, dst_ip) pairs and dst_ips currently covered by an active
        openflow block (_active_blocks; deliberately excludes
        _active_mobile_blocks -- the LOW_SLOW callers this feeds are
        openflow-only). For merging into analyze_low_slow's exclude_dsts
        / analyze_low_slow_single_source's exclude_pairs alongside the
        current cycle's own flagged_pairs/flagged_dsts, so a pair already
        under an active block from an EARLIER cycle's classification
        can't get a fresh, different classification once its volumetric
        signal drops out and the post-flood grace window
        (_RECENT_FLOOD_GRACE_CYCLES) expires.

        Without this, a stale DDoSCollector port-set entry for an already
        -blocked, now-finished attack (lingering up to
        LOW_SLOW_PORT_IDLE_TTL=90s with its old distinct-port count still
        >= LOW_SLOW_NEW_FLOWS) gets misread as a brand new LOW_SLOW
        attack once the grace window passes -- re-blocking the same
        attacker under the wrong label and replacing the original
        SYN_FLOOD action with a LOW_SLOW one. is_active_block() alone
        only silences the resulting *log line*/metric for that fresh
        (wrong) classification; this stops the reclassification itself
        from happening in the first place.
        """
        pairs = {(src, dst) for (src, dst, _port, _proto) in self._active_blocks}
        dsts = {dst for (_src, dst, _port, _proto) in self._active_blocks}
        return pairs, dsts

    def is_mobile_blocked(self, src_ip: str, dst_ip: str) -> bool:
        """
        True if this source (mobile UE or BNGBlaster session -- see
        config.settings.PER_SOURCE_MITIGATION_DOMAINS) already has an
        active per-source block toward this destination, regardless of
        attack type/protocol/port. Kept its original "_mobile" name (only
        mobile existed when it was written) -- _active_mobile_blocks is
        shared by every PER_SOURCE_MITIGATION_DOMAINS member, not mobile-
        only, despite the name.

        Queried by DDoSDetectionEngine.analyze_low_slow_mobile to exclude
        already-quarantined sources from its low-rate source count: a
        successful throttle (from ANY attack type -- UDP/SYN/ICMP flood,
        DDOS_DISTRIBUTED) drops a source's reported rate to near-zero,
        which falls squarely inside LOW_SLOW_MOBILE_MAX_PPS's "low rate"
        band -- without this exclusion, the mitigation's own side effect
        on a group of sources gets misread as a brand new LOW_SLOW attack
        forming on top of the one already being handled (observed: a DDOS_
        DISTRIBUTED block immediately followed by a LOW_SLOW detection
        for the exact same sources and destination, caused entirely by
        their own quarantine noise).
        """
        return any(key[0] == src_ip and key[1] == dst_ip for key in self._active_mobile_blocks)

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
        (src_ip, dst_ip) is currently under an active block — either that
        exact source individually (DDOS_DISTRIBUTED's per-source blocks)
        or a destination-wide "*" block (LOW_SLOW's flow-count variant,
        which has no per-source list to scope to).

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
        if not self._active_blocks:
            return

        wildcard_dsts = {
            dst_ip for (src_ip, dst_ip, _, _) in self._active_blocks if src_ip == "*"
        }
        blocked_pairs = {
            (src_ip, dst_ip) for (src_ip, dst_ip, _, _) in self._active_blocks if src_ip != "*"
        }

        if not wildcard_dsts and not blocked_pairs:
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

            if not src_ip:
                continue

            if dst_ip in wildcard_dsts or (src_ip, dst_ip) in blocked_pairs:
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

    def check_unblocks(self) -> List[MitigationAction]:
        """
        Re-evaluate every active openflow block. A block is released once
        its drop rule's own pps (see record_block_traffic — telemetry from
        the regular pipeline goes silent for a blocked flow, since its
        packets never reach packet_in again and FlowCollector excludes
        drop-rule entries) has stayed below UNBLOCK_RATIO of the
        triggering threshold for UNBLOCK_CONFIRM_CYCLES consecutive
        cycles — i.e. once the controller no longer "feels" the attack,
        confirmed rather than on a single quiet sample.

        Returns the unblock MitigationActions issued this cycle (empty if
        none) instead of logging them itself — the caller (ryu_controller_2.
        py's _run_pipeline) folds them into the same MITIGATION dashboard/
        logger line every other domain's actions go through, the same
        pattern check_mobile_unblocks() uses.
        """
        if not self._active_blocks:
            return []

        unblock_actions: List[MitigationAction] = []

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
                attack_type = self._active_blocks[key].attack_type

                self.of_mitigator.unblock(src_ip, dst_ip, dst_port, protocol)
                unblock_actions.append(MitigationAction(
                    domain="enterprise",
                    device_id="",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    action="unblock",
                    attack_type=attack_type,
                ))

                del self._active_blocks[key]
                del self._below_threshold_streak[key]
                self._forget_block_traffic(key)
                metrics.set_active_blocks(len(self._active_blocks))
                # Force re-validation: a destination that was just under
                # attack shouldn't get its forwarding rules trusted again
                # without going through at least one more clean cycle.
                self._validated_destinations.discard(dst_ip)

        return unblock_actions

    def check_mobile_unblocks(self, correlated: List[CorrelatedEvent]) -> List[MitigationAction]:
        """
        Re-evaluate every active per-source block (any
        config.settings.PER_SOURCE_MITIGATION_DOMAINS member -- kept this
        method's original "_mobile" name, see is_mobile_blocked's
        docstring). Unlike openflow's
        check_unblocks(), a successfully-quarantined UE's reported pps
        drops near zero *as soon as the throttle takes effect* — that's
        the mitigation working, not proof the attacker stopped. Using a
        pps-vs-threshold comparison here (the way check_unblocks() does
        for openflow, where a blocked flow's packets genuinely vanish
        from telemetry) would unblock almost immediately every time,
        let 1-2 cycles of full-rate traffic back through while the
        attacker is still active, get re-detected, and re-block — an
        observed block/unblock/reattack oscillation.

        The signal used instead is presence, not rate: a UE still inside
        its attack window keeps reporting telemetry toward the same
        dst_ip even while throttled to near-zero (see ul_traffic_
        simulator.py's UE.sample() -- dst_ip only reverts to the UE's
        normal destination once the attack genuinely stops). So a block
        is only released once this exact (src_ip, dst_ip, protocol) has
        produced *zero* matching telemetry events for UNBLOCK_CONFIRM_
        CYCLES consecutive cycles -- i.e. the UE stopped reporting
        toward that destination entirely, not just reporting less.

        Returns the unblock MitigationActions issued this cycle (empty if
        none) instead of logging them itself — the caller (ryu_controller_2.
        py's _run_pipeline) folds them into the same MITIGATION dashboard/
        logger line every other domain's actions go through, so mobile
        unblocks read exactly like an openflow one instead of a separate,
        differently-formatted message.
        """
        if not self._active_mobile_blocks:
            return []

        by_dst = {c.dst_ip: c for c in correlated}
        unblock_actions: List[MitigationAction] = []

        for key in list(self._active_mobile_blocks):
            src_ip, dst_ip, dst_port, protocol = key
            original = self._active_mobile_blocks[key]
            domain = original.domain

            # Domains in PRESENCE_BLIND_DOMAINS can't use the presence
            # signal below at all -- their block (BroadbandAdapter's
            # session-stop) doesn't throttle the source, it cuts it off
            # entirely, so collect() produces literally zero
            # TelemetryEvents for it while blocked. That's
            # indistinguishable from "the attacker stopped" under the
            # presence check, and confirmed on a real run to cause
            # exactly the oscillation that check was originally written
            # to prevent: BLOCK at t, telemetry vanishes (because it's
            # blocked, not because the attack ended), UNBLOCK fires after
            # UNBLOCK_CONFIRM_CYCLES, the still-active attacker
            # immediately gets re-detected and re-blocked. Held for a
            # fixed wall-clock window instead (the block's own `duration`
            # field, no streak/confirm-cycles gate -- elapsed time is
            # already a deliberate, complete signal) -- if the attacker
            # is still flooding once that window ends and gets
            # re-detected, fine, that's a fresh block with its own fresh
            # window, not an instant bounce.
            if domain in settings.PRESENCE_BLIND_DOMAINS:
                started_at = self._mobile_block_started_at.get(key, time.time())
                if time.time() - started_at < original.duration:
                    continue
            else:
                c = by_dst.get(dst_ip)
                # Matches on src_ip alone, not protocol -- neither
                # MobileNetworkAdapter nor BroadbandAdapter's collect()
                # can produce more than one TelemetryEvent per source per
                # cycle (one IMSI/session's single current row), so a
                # src_ip can't be ambiguous between protocols the way an
                # OpenFlow 5-tuple could be. Matching on protocol too
                # caused real false unblocks: the stored key's protocol
                # comes from DetectionResult, which carries either the
                # *normalized* tag (DDoSDetectionEngine._normalize_
                # protocol turns "TCP_SYN" into "TCP" for OpenFlow's
                # benefit) or a hardcoded placeholder ("UDP" for
                # analyze_low_slow_mobile's protocol-agnostic detections)
                # -- neither of which equals the real TelemetryEvent.
                # protocol ("TCP_SYN" or whatever the source actually
                # sends), so the comparison always failed and every
                # SYN_FLOOD/DDOS_DISTRIBUTED/LOW_SLOW block unblocked
                # itself after exactly UNBLOCK_CONFIRM_CYCLES regardless
                # of whether the attack was still running.
                still_present = c is not None and any(
                    e.domain == domain and e.src_ip == src_ip for e in c.events
                )

                if still_present:
                    self._mobile_below_threshold_streak[key] = 0
                    continue

                self._mobile_below_threshold_streak[key] = (
                    self._mobile_below_threshold_streak.get(key, 0) + 1
                )

                if self._mobile_below_threshold_streak[key] < self.UNBLOCK_CONFIRM_CYCLES:
                    continue

            # Reaching here means either the presence-streak gate above
            # already confirmed UNBLOCK_CONFIRM_CYCLES of absence, or
            # (PRESENCE_BLIND_DOMAINS) the fixed wall-clock window already
            # elapsed -- either way, release it now.
            #
            # Carries the original block's attack_type/device_id through
            # so the dashboard/logger line reads "UNTHROTTLE ... gNB=1
            # ..." instead of a blank attack_type or "gNB=unknown" -- same
            # gNB/BNG the source was throttled on, since releasing it is
            # the same control-plane operation, just in reverse.
            attack_type = original.attack_type

            unblock_action = MitigationAction(
                domain=domain,
                device_id=original.device_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                action="unblock",
                attack_type=attack_type,
            )
            adapter = self._adapters.get(domain)
            if adapter:
                adapter.apply_mitigation(unblock_action)
            unblock_actions.append(unblock_action)

            del self._active_mobile_blocks[key]
            self._mobile_below_threshold_streak.pop(key, None)
            self._mobile_block_started_at.pop(key, None)
            self._validated_destinations.discard(dst_ip)

        return unblock_actions
