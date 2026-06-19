import math
from collections import defaultdict
from typing import Dict, List, Optional

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
    - LOW_SLOW         : many concurrent micro-flows with minimal bytes (placeholder)
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

    # ------------------------------------------------------------------
    # Internal classification logic
    # ------------------------------------------------------------------

    def _classify(self, event: CorrelatedEvent) -> Optional[DetectionResult]:
        """
        Classify a single CorrelatedEvent.
        Returns a DetectionResult if a threshold is exceeded, else None.
        """
        tcp_pps  = self._sum_pps(event.events, "TCP")
        udp_pps  = self._sum_pps(event.events, "UDP")
        icmp_pps = self._sum_pps(event.events, "ICMP")

        attack_type: Optional[str] = None
        score: float = 0.0

        if tcp_pps > settings.SYN_THRESHOLD:
            attack_type = "SYN_FLOOD"
            score = tcp_pps / settings.SYN_THRESHOLD

        elif udp_pps > settings.UDP_THRESHOLD:
            attack_type = "UDP_FLOOD"
            score = udp_pps / settings.UDP_THRESHOLD

        elif icmp_pps > settings.ICMP_THRESHOLD:
            attack_type = "ICMP_FLOOD"
            score = icmp_pps / settings.ICMP_THRESHOLD

        if attack_type is None:
            # No single source is over threshold — check whether the
            # destination is being flooded by many distinct sources at once.
            return self._classify_distributed(event)

        # Base confidence derived from how far above threshold we are
        base_confidence = min(score / 10.0, 1.0)

        # Boost if the attack is visible across more than one domain
        multidomain = len(event.domains) > 1
        confidence = min(
            base_confidence * (self.MULTIDOMAIN_BOOST if multidomain else 1.0),
            1.0
        )

        # Use the highest-pps event as the representative source/device —
        # the attacking source, not just whichever event happened to be first
        representative: TelemetryEvent = max(event.events, key=lambda e: e.pps)

        return DetectionResult(
            domain=representative.domain,
            device_id=representative.device_id,
            src_ip=representative.src_ip,
            dst_ip=event.dst_ip,
            dst_port=representative.dst_port,
            protocol=representative.protocol,
            attack_type=attack_type,
            score=score,
            confidence=confidence,
        )

    @staticmethod
    def _sum_pps(events: List[TelemetryEvent], protocol: str) -> float:
        return sum(e.pps for e in events if e.protocol == protocol)

    def _classify_distributed(self, event: CorrelatedEvent) -> Optional[DetectionResult]:
        """
        Detect a distributed/spoofed-source flood: aggregate volume toward
        this destination exceeds DIST_PPS_THRESHOLD, coming from at least
        DIST_MIN_SOURCES distinct source IPs whose individual contributions
        are distributed close to evenly (high normalized entropy) — unlike
        a single attacker (low entropy, one dominant source).
        """
        total_pps = sum(e.pps for e in event.events)

        if total_pps < settings.DIST_PPS_THRESHOLD:
            return None

        pps_by_src: Dict[str, float] = defaultdict(float)
        for e in event.events:
            pps_by_src[e.src_ip] += e.pps

        if len(pps_by_src) < settings.DIST_MIN_SOURCES:
            return None

        entropy = self._normalized_entropy(pps_by_src.values())

        if entropy < settings.DIST_ENTROPY_THRESHOLD:
            return None

        score = total_pps / settings.DIST_PPS_THRESHOLD

        multidomain = len(event.domains) > 1
        confidence = min(
            entropy * (self.MULTIDOMAIN_BOOST if multidomain else 1.0),
            1.0
        )

        # No single attacking IP to point at — representative is just used
        # for domain/device/protocol/port context.
        representative: TelemetryEvent = max(event.events, key=lambda e: e.pps)

        return DetectionResult(
            domain=representative.domain,
            device_id=representative.device_id,
            src_ip="*",
            dst_ip=event.dst_ip,
            dst_port=representative.dst_port,
            protocol=representative.protocol,
            attack_type="DDOS_DISTRIBUTED",
            score=score,
            confidence=confidence,
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
