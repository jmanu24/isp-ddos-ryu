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

    def analyze(self, correlated: List[CorrelatedEvent]) -> List[DetectionResult]:
        """
        Analyze a list of CorrelatedEvents and return detected attacks.
        """
        results = []

        for event in correlated:
            detection = self._classify(event)
            if detection:
                results.append(detection)

        return results

    def analyze_low_slow(self, flow_counts: Dict[str, int]) -> List[DetectionResult]:
        """
        flow_counts: dst_ip -> number of currently-stalled, low-byte flows
        toward it this cycle (FlowCollector.count_low_volume_flows, via
        OpenFlowAdapter.collect_low_volume_flow_counts). Flagged once that
        count crosses LOW_SLOW_NEW_FLOWS — there's no single attacker to
        point at here (could be one source opening many connections, or
        many sources each opening a few), so src_ip is "*", same as a
        distributed flood.
        """
        results = []

        for dst_ip, count in flow_counts.items():
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
        self, port_counts: Dict[Tuple[str, str], int]
    ) -> List[DetectionResult]:
        """
        port_counts: (src_ip, dst_ip) -> distinct source ports that src_ip
        has used toward dst_ip recently (DDoSCollector.get_connection_port_counts,
        via OpenFlowAdapter.get_connection_port_counts). Catches the classic
        single-attacker Slowloris pattern — one source opening many real
        connections to the same destination — which analyze_low_slow's
        flow-count check can't see: those connections all collapse into one
        L3 forwarding rule (same src_ip, same dst_ip), so OpenFlow itself
        never represents them as separate flows. Unlike analyze_low_slow,
        there IS a single attacker to point at here.
        """
        results = []

        for (src_ip, dst_ip), distinct_ports in port_counts.items():
            if distinct_ports < settings.LOW_SLOW_NEW_FLOWS:
                continue

            score = distinct_ports / settings.LOW_SLOW_NEW_FLOWS
            confidence = min(score / 2.0, 1.0)

            results.append(DetectionResult(
                domain="openflow",
                device_id="",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=0,
                protocol="IP",
                attack_type="LOW_SLOW",
                score=score,
                confidence=confidence,
            ))

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
        multidomain = len(event.domains) > 1

        if is_distributed:
            # No single attacker to scope a switch/port block to — many
            # sources, so the representative is just domain/protocol/port
            # context, picked from whichever event has the most pps.
            representative = self._pick_representative(proto_events)
            confidence = min(entropy * (self.MULTIDOMAIN_BOOST if multidomain else 1.0), 1.0)
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

    @staticmethod
    def _sum_pps(events: List[TelemetryEvent], protocol: str) -> float:
        return sum(e.pps for e in events if e.protocol == protocol)

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

        multidomain = len(event.domains) > 1
        confidence = min(
            entropy * (self.MULTIDOMAIN_BOOST if multidomain else 1.0),
            1.0
        )

        # No single attacking IP to point at — representative is just used
        # for domain/device/protocol/port context.
        representative: TelemetryEvent = max(candidate_events, key=lambda e: e.pps)

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
