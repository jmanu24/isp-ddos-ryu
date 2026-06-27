import math
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from core.models import CorrelatedEvent, DetectionResult, TelemetryEvent
import config.settings as settings


class DDoSDetectionEngine:
    """
    DDoS Detection Engine.

    Receives CorrelatedEvents from the Multidomain Correlation layer and
    classifies them by attack type using per-protocol thresholds defined
    in config/settings.py.

    Attack types detected:
    - SYN_FLOOD        : high TCP PPS toward the same destination
    - UDP_FLOOD        : high UDP PPS toward the same destination
    - ICMP_FLOOD       : high ICMP PPS toward the same destination
    - LOW_SLOW         : many concurrent connections toward one destination
                         that have stayed open a while but barely sent any
                         data (Slowloris-style) — caught by flow *count*,
                         not pps/bps, since each connection alone never
                         crosses any volumetric threshold
    - DDOS_DISTRIBUTED : many distinct (often spoofed) sources, each below the
                         single-source thresholds, jointly flooding one
                         destination with a near-uniform (high-entropy)
                         traffic distribution across source IPs

    Confidence is boosted when the same destination is targeted from
    multiple network domains simultaneously (multidomain attack pattern).
    """

    # Confidence multiplier when attack spans more than one domain
    MULTIDOMAIN_BOOST = 1.3

    # How many cycles a (src_ip, dst_ip) pair / dst_ip keeps counting as
    # "recently a volumetric flood" after the LAST cycle it was actually
    # classified as one. Exists to close a real race in
    # analyze_low_slow_single_source/analyze_low_slow's exclusion:
    # OpenFlow's forwarding rule for an unvalidated (under-attack-from-
    # the-start) destination is a short-lived PROVISIONAL rule
    # (LearningSwitch.PROVISIONAL_TIMEOUT=2s) that gets torn down and
    # reinstalled with its counters reset to 0 roughly every 2s --
    # FlowCollector sees that reset as a negative byte/packet delta and
    # silently skips that one sample (collectors/flow_collector.py), so
    # the volumetric check has periodic one-cycle gaps with no data at
    # all. Meanwhile DDoSCollector's distinct-source-port count (which is
    # what catches a single-source low-and-slow signature) never resets
    # and keeps climbing every cycle regardless -- a flood tool that
    # randomizes its source port per packet (hping3 --flood does, by
    # default) will eventually cross LOW_SLOW_NEW_FLOWS even though it's
    # really just one continuous SYN flood. If that crossing happens to
    # land on exactly one of the volumetric check's data-gap cycles, the
    # *same-cycle-only* exclusion this engine used to rely on has nothing
    # to exclude with, LOW_SLOW fires and blocks the flow -- and since
    # the block then silences all further packets, the volumetric
    # classification never gets another chance to set the record straight.
    # A multi-cycle grace period instead of a same-cycle-only check
    # absorbs that gap.
    #
    # Must stay several multiples of PROVISIONAL_TIMEOUT (2s) in REAL
    # time, not just "a few cycles" -- at config.settings.COLLECT_INTERVAL
    # =0.5s, 6 cycles is only 3s (1.5x PROVISIONAL_TIMEOUT), barely enough
    # margin to bridge even one reset gap. Confirmed on a real run: after
    # the grace period from one SYN_FLOOD detection expired, the very
    # next data-gap cycle let LOW_SLOW win the classification race again,
    # making SYN_FLOOD/LOW_SLOW alternate every few cycles for the same
    # ongoing hping3 flood instead of staying SYN_FLOOD. Raised to give
    # ~5x margin over PROVISIONAL_TIMEOUT in real time (20 * 0.5s = 10s).
    _RECENT_FLOOD_GRACE_CYCLES = 20

    def __init__(self):
        # dst_ip -> consecutive cycles with >= LOW_SLOW_MOBILE_MIN_SOURCES
        # distinct low-rate mobile UEs seen toward it (analyze_low_slow_
        # mobile). Persistent across calls -- this is what turns "a few
        # quiet UEs this one cycle" into a real signal, since any single
        # cycle's count alone is indistinguishable from coincidence.
        self._mobile_low_rate_streak: Dict[str, int] = {}

        # (src_ip, dst_ip) -> cycles remaining in its post-flood grace
        # period, and dst_ip -> same, for the flow-count-only LOW_SLOW
        # variant. Refreshed to _RECENT_FLOOD_GRACE_CYCLES every cycle a
        # pair/dst is actually classified as a volumetric flood by
        # analyze(); decremented (and dropped once it hits 0) every other
        # cycle. See _RECENT_FLOOD_GRACE_CYCLES above for why this needs
        # to outlive a single cycle instead of being recomputed fresh
        # each time.
        self._recent_flood_pairs: Dict[Tuple[str, str], int] = {}
        self._recent_flood_dsts: Dict[str, int] = {}

    def analyze(self, correlated: List[CorrelatedEvent]) -> List[DetectionResult]:
        """
        Analyze a list of CorrelatedEvents and return detected attacks.
        """
        results = []
        flagged_pairs_this_cycle = set()
        flagged_dsts_this_cycle = set()

        for event in correlated:
            detection = self._classify(event)
            if detection:
                results.append(detection)
                flagged_dsts_this_cycle.add(detection.dst_ip)
                if detection.attack_type == "DDOS_DISTRIBUTED" and detection.sources:
                    for source in detection.sources:
                        flagged_pairs_this_cycle.add((source, detection.dst_ip))
                else:
                    flagged_pairs_this_cycle.add((detection.src_ip, detection.dst_ip))

        self._refresh_recent_floods(flagged_pairs_this_cycle, flagged_dsts_this_cycle)

        return results

    def _refresh_recent_floods(self, flagged_pairs, flagged_dsts) -> None:
        """See _RECENT_FLOOD_GRACE_CYCLES for why this exists."""
        for pair in flagged_pairs:
            self._recent_flood_pairs[pair] = self._RECENT_FLOOD_GRACE_CYCLES
        for pair in list(self._recent_flood_pairs):
            if pair not in flagged_pairs:
                self._recent_flood_pairs[pair] -= 1
                if self._recent_flood_pairs[pair] <= 0:
                    del self._recent_flood_pairs[pair]

        for dst in flagged_dsts:
            self._recent_flood_dsts[dst] = self._RECENT_FLOOD_GRACE_CYCLES
        for dst in list(self._recent_flood_dsts):
            if dst not in flagged_dsts:
                self._recent_flood_dsts[dst] -= 1
                if self._recent_flood_dsts[dst] <= 0:
                    del self._recent_flood_dsts[dst]

    def recent_flood_pairs(self) -> set:
        """(src_ip, dst_ip) pairs classified as a volumetric flood within
        the last _RECENT_FLOOD_GRACE_CYCLES calls to analyze() -- merge
        into exclude_pairs for analyze_low_slow_single_source so a single
        cycle's flow-stats data gap can't let LOW_SLOW fire uncontested."""
        return set(self._recent_flood_pairs)

    def recent_flood_dsts(self) -> set:
        """Same as recent_flood_pairs(), for analyze_low_slow's dst-only
        exclude_dsts."""
        return set(self._recent_flood_dsts)

    def analyze_low_slow(
        self, flow_counts: Dict[str, int], exclude_dsts=frozenset()
    ) -> List[DetectionResult]:
        """
        flow_counts: dst_ip -> number of currently-stalled, low-byte flows
        toward it this cycle (FlowCollector.count_low_volume_flows, via
        OpenFlowAdapter.collect_low_volume_flow_counts). Flagged once that
        count crosses LOW_SLOW_NEW_FLOWS — there's no single attacker to
        point at here (could be one source opening many connections, or
        many sources each opening a few), so src_ip is "*", same as a
        distributed flood.

        exclude_dsts: destinations already flagged by a volumetric flood
        this same cycle (analyze()) — skipped here so a genuine high-pps
        flood whose tool happens to randomize its source port (hping3
        --flood does, by default) doesn't *also* get reported as LOW_SLOW
        just because that incidentally looks like "many distinct ports".
        """
        results = []

        for dst_ip, count in flow_counts.items():
            if dst_ip in exclude_dsts:
                continue

            if count < settings.LOW_SLOW_NEW_FLOWS:
                continue

            score = count / settings.LOW_SLOW_NEW_FLOWS
            confidence = min(score / 2.0, 1.0)

            results.append(DetectionResult(
                domain="openflow",
                device_id="",
                src_ip="*",
                dst_ip=dst_ip,
                dst_port=0,
                protocol="IP",
                attack_type="LOW_SLOW",
                score=score,
                confidence=confidence,
            ))

        return results

    def analyze_low_slow_single_source(
        self, port_counts: Dict[Tuple[str, str], dict], exclude_pairs=frozenset()
    ) -> List[DetectionResult]:
        """
        port_counts: (src_ip, dst_ip) -> {"count", "dst_port", "protocol"}
        (DDoSCollector.get_connection_port_counts, via
        OpenFlowAdapter.get_connection_port_counts). Catches the classic
        single-attacker Slowloris pattern — one source opening many real
        connections to the same destination — which analyze_low_slow's
        flow-count check can't see: those connections all collapse into one
        L3 forwarding rule (same src_ip, same dst_ip), so OpenFlow itself
        never represents them as separate flows. Unlike analyze_low_slow,
        there IS a single attacker — and a known target port/protocol — to
        scope a block to here.

        exclude_pairs: (src_ip, dst_ip) pairs already flagged by a
        volumetric flood this same cycle (analyze()) — a fast SYN/UDP
        flood from a tool that randomizes its source port per packet
        (hping3 --flood does, by default) looks identical to "many
        distinct connections" otherwise, and would get double-reported
        as LOW_SLOW for the exact same traffic SYN_FLOOD already covers.

        info["age"] (seconds since the pair's first packet) must also
        clear settings.LOW_SLOW_MIN_AGE before its port count counts at
        all -- exclude_pairs alone isn't enough, since it only protects a
        destination AFTER the volumetric check has had a fair shot (at
        least one full FlowCollector sample pair). A fast hping3 --flood
        can rack up LOW_SLOW_NEW_FLOWS distinct source ports within the
        very first fraction of a second (table-miss packet-in bursts
        before its L3 forwarding rule is even programmed), well before
        the volumetric path's first valid two-sample pps reading exists
        to populate exclude_pairs in the first place. Confirmed on a real
        run: this exact race made a sustained SYN flood get classified as
        LOW_SLOW on its very first detection almost every time. Real
        Slowloris-style attacks open their connections slowly over
        minutes, so requiring this age costs them nothing.
        """
        results = []

        for (src_ip, dst_ip), info in port_counts.items():
            if (src_ip, dst_ip) in exclude_pairs:
                continue

            if info.get("age", 0) < settings.LOW_SLOW_MIN_AGE:
                continue

            distinct_ports = info["count"]

            if distinct_ports < settings.LOW_SLOW_NEW_FLOWS:
                continue

            score = distinct_ports / settings.LOW_SLOW_NEW_FLOWS
            confidence = min(score / 2.0, 1.0)

            results.append(DetectionResult(
                domain="openflow",
                device_id="",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=info["dst_port"],
                protocol=info["protocol"],
                attack_type="LOW_SLOW",
                score=score,
                confidence=confidence,
            ))

        return results

    def analyze_low_slow_mobile(
        self, correlated: List[CorrelatedEvent], exclude_dsts=frozenset(), is_blocked=None
    ) -> List[DetectionResult]:
        """
        Low-and-slow detection for domains with no connection/flow-count
        visibility (config.settings.PER_SOURCE_MITIGATION_DOMAINS --
        mobile's per-UE KPM and the broadband/BNGBlaster domain's
        per-session counters both report one throughput number per
        source, no socket-level visibility). Kept this method's original
        "_mobile" name (only mobile existed when it was written) even
        though it's domain-generic now, rather than rename it and update
        every call site for what's purely a label change.

        OpenFlow's two LOW_SLOW variants above both key off connection/flow
        *count* -- a signal that visibility gap rules out. Duration alone
        doesn't work as a substitute either: every benign UE/session in
        this pipeline sends a flat, continuous trickle to the same
        destination for as long as it's connected, so "this source has had
        a low nonzero rate for a long time" would eventually flag every
        ordinary one.

        What's actually anomalous is many distinct sources simultaneously
        holding a low, sub-threshold rate toward the *same* destination --
        the analog of "many slow connections at once" rather than "one
        connection, slowly". So this counts, per destination, how many
        distinct sources (across any domain in PER_SOURCE_MITIGATION_DOMAINS)
        have 0 < pps <= LOW_SLOW_MOBILE_MAX_PPS this cycle, and only flags
        it once that count has held at or above LOW_SLOW_MOBILE_MIN_SOURCES
        for LOW_SLOW_MOBILE_MIN_CYCLES consecutive cycles. No single
        attacker to point at -- src_ip="*", with the contributing sources'
        IPs carried in `sources` so orchestration can quarantine each of
        them individually (mirrors DDOS_DISTRIBUTED's per-source list,
        since unlike OpenFlow there's no destination-wide network lever
        here). Mixing sources from more than one PER_SOURCE_MITIGATION_
        DOMAINS member toward the same destination in one streak is
        intentional, not a bug -- a multidomain low-and-slow attack is a
        real (if rarer) case this should still catch.

        exclude_dsts: destinations already flagged by a volumetric flood
        this cycle (analyze()) -- a real flood already being handled
        shouldn't also get reported as LOW_SLOW just because some of its
        traffic happens to sit under the low-rate ceiling.

        is_blocked: optional Callable[[src_ip, dst_ip], bool] (OrchestrationController.
        is_mobile_blocked) -- excludes UEs already under an active mobile
        block from the count. A successful quarantine from ANY attack
        type drops a UE's reported rate to near-zero, which falls inside
        this detector's own low-rate band; without this exclusion, that
        mitigation side effect on a group of UEs reads as a brand new
        LOW_SLOW attack forming on top of the one already being handled.
        """
        results = []
        seen_dsts = set()

        for event in correlated:
            if event.dst_ip in exclude_dsts:
                continue

            low_rate_sources = {
                e.src_ip for e in event.events
                if e.domain in settings.PER_SOURCE_MITIGATION_DOMAINS
                and 0 < e.pps <= settings.LOW_SLOW_MOBILE_MAX_PPS
                and not (is_blocked and is_blocked(e.src_ip, event.dst_ip))
            }
            seen_dsts.add(event.dst_ip)

            if len(low_rate_sources) < settings.LOW_SLOW_MOBILE_MIN_SOURCES:
                self._mobile_low_rate_streak[event.dst_ip] = 0
                continue

            streak = self._mobile_low_rate_streak.get(event.dst_ip, 0) + 1
            self._mobile_low_rate_streak[event.dst_ip] = streak

            if streak < settings.LOW_SLOW_MOBILE_MIN_CYCLES:
                continue

            # 1.3x headroom at the documented minimum source count, not a
            # plain count/MIN_SOURCES ratio -- DecisionEngine weights
            # LOW_SLOW at 1.2 and requires score*confidence*weight >=
            # DECISION_THRESHOLD(1.5). A plain ratio caps at exactly 1.0
            # when count==MIN_SOURCES, and confidence (below) caps at 1.0
            # too, so 1.0*1.0*1.2=1.2 could never clear 1.5 no matter how
            # long the attack persisted -- meeting the stated minimum
            # would be detected (logged every cycle, see is_active_block)
            # but silently never actually mitigated. The 1.3 multiplier
            # makes the documented minimum genuinely sufficient: 1.3*1.2=
            # 1.56 clears 1.5 right at MIN_SOURCES/MIN_CYCLES, instead of
            # requiring undocumented extra sources to ever cross threshold.
            score = 1.3 * (len(low_rate_sources) / settings.LOW_SLOW_MOBILE_MIN_SOURCES)
            # Full confidence as soon as the persistence requirement is
            # actually met (unlike the openflow LOW_SLOW variants' .../2.0
            # softening) -- MIN_CYCLES is already the deliberate
            # confirmation period (see its settings.py comment), so
            # reaching it isn't a "maybe", it's the point this detector
            # exists to wait for.
            confidence = min(streak / settings.LOW_SLOW_MOBILE_MIN_CYCLES, 1.0)

            # Real gnb_id/dst_port/protocol from one of the actual
            # contributing UEs, not a hardcoded placeholder -- this
            # detector doesn't need any of these to decide (it's a
            # source-count signature, not protocol/cell-specific), but
            # logging fake values when the simulator was configured with
            # real ones made the controller's own MITIGATION line look
            # inconsistent with what was simulated, and device_id is
            # exactly the gNB/E2-node parameter a real RC throttle would
            # need to locate the UE. All contributing UEs share the same
            # tag in practice (one attack config applied to the whole
            # group), so any single representative is correct.
            representative = next(
                e for e in event.events if e.src_ip in low_rate_sources
            )
            # Each contributing UE's OWN device_id (gNB) -- unlike
            # dst_port/protocol, gnb_id is NOT something one attack config
            # applies identically to the whole group; UEs spread across
            # multiple simulated gNBs (ul_traffic_simulator.py's
            # --gnb-count) each keep their real one. See
            # DetectionResult.source_device_ids.
            source_device_ids = {
                e.src_ip: e.device_id for e in event.events if e.src_ip in low_rate_sources
            }

            results.append(DetectionResult(
                domain=representative.domain,
                device_id=representative.device_id,
                src_ip="*",
                dst_ip=event.dst_ip,
                dst_port=representative.dst_port,
                protocol=representative.protocol,
                attack_type="LOW_SLOW",
                score=score,
                confidence=confidence,
                sources=list(low_rate_sources),
                source_device_ids=source_device_ids,
            ))

        # Forget destinations that didn't appear in `correlated` at all
        # this cycle (e.g. every contributing UE went idle/disconnected) --
        # otherwise a stale streak would keep counting up untouched and
        # could fire later from a single coincidental cycle.
        for dst_ip in list(self._mobile_low_rate_streak):
            if dst_ip not in seen_dsts:
                del self._mobile_low_rate_streak[dst_ip]

        return results

    # ------------------------------------------------------------------
    # Internal classification logic
    # ------------------------------------------------------------------

    # Per-protocol (attack_type, pps threshold) checked in order. SYN_FLOOD
    # checks "TCP_SYN" specifically (bare SYN, no ACK — a connection
    # attempt) rather than all TCP traffic, so a flood of *completed*
    # connections (e.g. Slowloris-style: real handshakes, then a slow
    # trickle) doesn't get misread as a SYN flood just because it's TCP —
    # it should surface as LOW_SLOW instead once the connections age in.
    _PROTOCOL_CHECKS = (
        ("TCP_SYN", "SYN_FLOOD", "SYN_THRESHOLD"),
        ("UDP", "UDP_FLOOD", "UDP_THRESHOLD"),
        ("ICMP", "ICMP_FLOOD", "ICMP_THRESHOLD"),
    )

    def _classify(self, event: CorrelatedEvent) -> Optional[DetectionResult]:
        """
        Classify a single CorrelatedEvent.

        For each protocol whose aggregate pps exceeds its threshold, the
        source-IP distribution decides *how* to classify it — concentrated
        in one/few sources (low entropy) means a single attacker; spread
        evenly across many distinct sources (high entropy) means a
        distributed/spoofed-source flood. This check happens before picking
        an attack_type, so a high aggregate total doesn't get blamed on
        whichever single source happened to have the most pps that cycle.
        """
        for protocol, attack_type, threshold_name in self._PROTOCOL_CHECKS:
            threshold = getattr(settings, threshold_name)

            proto_events = [e for e in event.events if e.protocol == protocol]
            total_pps = sum(e.pps for e in proto_events)

            if total_pps <= threshold:
                continue

            return self._build_result(event, proto_events, total_pps, threshold, attack_type)

        # No single protocol's aggregate crossed its threshold — still check
        # the protocol-agnostic case (e.g. raw/no-flag floods tagged "IP").
        return self._classify_distributed(event, event.events, settings.DIST_PPS_THRESHOLD)

    def _build_result(
        self,
        event: CorrelatedEvent,
        proto_events: List[TelemetryEvent],
        total_pps: float,
        threshold: float,
        single_source_attack_type: str,
    ) -> DetectionResult:
        """
        Decide, for traffic that already crossed a protocol's threshold,
        whether it's concentrated in one source (single-source flood) or
        spread across many (distributed flood), and build the matching
        DetectionResult.
        """
        pps_by_src: Dict[str, float] = defaultdict(float)
        for e in proto_events:
            pps_by_src[e.src_ip] += e.pps

        distinct_sources = len(pps_by_src)
        entropy = self._normalized_entropy(pps_by_src.values())

        is_distributed = (
            distinct_sources >= settings.DIST_MIN_SOURCES
            and entropy >= settings.DIST_ENTROPY_THRESHOLD
        )

        score = total_pps / threshold
        total_bps = sum(e.bps for e in proto_events)
        multidomain = len(event.domains) > 1

        if is_distributed:
            # No single attacker to scope a switch/port block to — many
            # sources, so the representative is just domain/protocol/port
            # context, picked from whichever event has the most pps.
            representative = self._pick_representative(proto_events)
            confidence = min(entropy * (self.MULTIDOMAIN_BOOST if multidomain else 1.0), 1.0)
            # See DetectionResult.source_device_ids -- each contributing
            # source's own device_id (e.g. a mobile UE's real gNB), not
            # the single representative event's.
            source_device_ids = {e.src_ip: e.device_id for e in proto_events}
            return DetectionResult(
                domain=representative.domain,
                device_id=representative.device_id,
                src_ip="*",
                dst_ip=event.dst_ip,
                dst_port=representative.dst_port,
                protocol=self._normalize_protocol(representative.protocol),
                attack_type="DDOS_DISTRIBUTED",
                score=score,
                confidence=confidence,
                sources=list(pps_by_src.keys()),
                source_device_ids=source_device_ids,
                pps=total_pps,
                bps=total_bps,
            )

        # Single attacker — narrow down to its own events first, then among
        # those prefer one tagged with a real ingress port (from packet-in)
        # over a flow-stats-derived one (which never carries in_port), so
        # mitigation can scope the block to the switch+port closest to it.
        dominant_src = max(pps_by_src, key=pps_by_src.get)
        dominant_events = [e for e in proto_events if e.src_ip == dominant_src]
        representative = self._pick_representative(dominant_events)

        base_confidence = min(score / 10.0, 1.0)
        confidence = min(base_confidence * (self.MULTIDOMAIN_BOOST if multidomain else 1.0), 1.0)

        return DetectionResult(
            domain=representative.domain,
            device_id=representative.device_id,
            src_ip=representative.src_ip,
            dst_ip=event.dst_ip,
            dst_port=representative.dst_port,
            protocol=self._normalize_protocol(representative.protocol),
            attack_type=single_source_attack_type,
            score=score,
            confidence=confidence,
            in_port=representative.in_port,
            pps=total_pps,
            bps=total_bps,
        )

    @staticmethod
    def _normalize_protocol(protocol: str) -> str:
        """
        "TCP_SYN" is an internal-only tag distinguishing bare SYN packets
        for SYN_FLOOD matching — mitigation/openflow_mitigator.py's L4
        match builder only knows "TCP"/"UDP"/"ICMP", so it's collapsed
        back to "TCP" before ever leaving the detection engine.
        """
        return "TCP" if protocol == "TCP_SYN" else protocol

    @staticmethod
    def _pick_representative(events: List[TelemetryEvent]) -> TelemetryEvent:
        """
        Prefer an event tagged with a real ingress port (in_port != 0,
        meaning it came from packet-in) over a flow-stats-derived one,
        which never carries in_port. Among the preferred pool, pick the
        highest-pps event.
        """
        tagged = [e for e in events if e.in_port]
        pool = tagged if tagged else events
        return max(pool, key=lambda e: e.pps)

    def _classify_distributed(
        self,
        event: CorrelatedEvent,
        candidate_events: List[TelemetryEvent],
        pps_threshold: float,
    ) -> Optional[DetectionResult]:
        """
        Protocol-agnostic fallback distributed-flood check, used only when
        no single protocol's aggregate pps crossed its own threshold (e.g.
        raw IP traffic with no recognizable L4 protocol).
        """
        total_pps = sum(e.pps for e in candidate_events)

        if total_pps < pps_threshold:
            return None

        pps_by_src: Dict[str, float] = defaultdict(float)
        for e in candidate_events:
            pps_by_src[e.src_ip] += e.pps

        if len(pps_by_src) < settings.DIST_MIN_SOURCES:
            return None

        entropy = self._normalized_entropy(pps_by_src.values())

        if entropy < settings.DIST_ENTROPY_THRESHOLD:
            return None

        score = total_pps / pps_threshold
        total_bps = sum(e.bps for e in candidate_events)

        multidomain = len(event.domains) > 1
        confidence = min(
            entropy * (self.MULTIDOMAIN_BOOST if multidomain else 1.0),
            1.0
        )

        # No single attacking IP to point at — representative is just used
        # for domain/device/protocol/port context.
        representative: TelemetryEvent = max(candidate_events, key=lambda e: e.pps)
        # See DetectionResult.source_device_ids -- each contributing
        # source's own device_id (e.g. a mobile UE's real gNB), not the
        # single representative event's.
        source_device_ids = {e.src_ip: e.device_id for e in candidate_events}

        return DetectionResult(
            domain=representative.domain,
            device_id=representative.device_id,
            src_ip="*",
            dst_ip=event.dst_ip,
            dst_port=representative.dst_port,
            protocol=self._normalize_protocol(representative.protocol),
            attack_type="DDOS_DISTRIBUTED",
            score=score,
            confidence=confidence,
            sources=list(pps_by_src.keys()),
            source_device_ids=source_device_ids,
            pps=total_pps,
            bps=total_bps,
        )

    @staticmethod
    def _normalized_entropy(weights) -> float:
        """
        Shannon entropy of a weight distribution, normalized to [0, 1] by
        the maximum possible entropy for that number of buckets (uniform
        distribution). 1.0 means traffic is split perfectly evenly across
        all sources; values near 0 mean it's concentrated in a few.
        """
        total = sum(weights)
        if total <= 0:
            return 0.0

        probs = [w / total for w in weights if w > 0]

        if len(probs) <= 1:
            return 0.0

        entropy = -sum(p * math.log2(p) for p in probs)
        max_entropy = math.log2(len(probs))

        return entropy / max_entropy if max_entropy > 0 else 0.0
