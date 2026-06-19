from typing import Dict, List, Tuple

import config.settings as settings
from core.models import CorrelatedEvent, DetectionResult, MitigationAction
from decision.engine import DecisionEngine, Decision
from telemetry.base import DomainAdapter
from mitigation.openflow_mitigator import OpenFlowMitigator


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

    def __init__(self, adapters: List[DomainAdapter]):
        # Index adapters by domain name for O(1) dispatch
        self._adapters: Dict[str, DomainAdapter] = {
            a.domain_name: a for a in adapters
        }
        self._decision_engine = DecisionEngine()
        self.of_mitigator = OpenFlowMitigator()

        # (src_ip, dst_ip, dst_port, protocol) -> MitigationAction currently
        # enforced, only for the openflow domain (the only one with a real
        # drop-rule backend so far).
        self._active_blocks: Dict[Tuple[str, str, int, str], MitigationAction] = {}

        # Same keys -> count of consecutive cycles seen below the unblock
        # threshold. Reset to 0 whenever traffic rises back above it.
        self._below_threshold_streak: Dict[Tuple[str, str, int, str], int] = {}

    # ------------------------------------------------------------------
    # Datapath lifecycle (called from the Ryu controller)
    # ------------------------------------------------------------------

    def register_datapath(self, datapath) -> None:
        self.of_mitigator.register(datapath)

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
        """
        if not detections:
            return []

        # Convert DetectionResults to the dict format expected by DecisionEngine
        det_dicts = [
            {
                "type": d.attack_type,
                "src_ip": d.src_ip,
                "score": d.score * d.confidence,
            }
            for d in detections
        ]

        decision: Decision = self._decision_engine.evaluate(det_dicts)

        if decision is None:
            return []

        actions = self._build_actions(decision, detections)

        for action in actions:
            self._dispatch(action)

        return actions

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

            actions.append(MitigationAction(
                domain=d.domain,
                device_id=d.device_id,
                src_ip=decision.src_ip,
                dst_ip=d.dst_ip,
                dst_port=d.dst_port,
                protocol=d.protocol,
                action=action_type,
            ))

        return actions

    @staticmethod
    def _action_for(attack_type: str, domain: str) -> str:
        """Map attack type + domain to a concrete mitigation action string."""
        if domain == "bgp":
            return "bgp_blackhole"
        if attack_type in ("SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD"):
            return "block"
        return "rate_limit"

    def _dispatch(self, action: MitigationAction) -> None:
        """Send action to the correct backend."""
        if action.domain == "openflow":
            self.of_mitigator.apply(action)

            if action.action == "block":
                key = (action.src_ip, action.dst_ip, action.dst_port, action.protocol)
                self._active_blocks[key] = action
                self._below_threshold_streak[key] = 0

            return

        adapter = self._adapters.get(action.domain)

        if adapter:
            adapter.apply_mitigation(action)
        else:
            print(
                f"[ORCHESTRATION] No adapter registered "
                f"for domain '{action.domain}'"
            )

    # ------------------------------------------------------------------
    # Unblocking — driven by the current volume of each blocked flow
    # ------------------------------------------------------------------

    def check_unblocks(self, correlated: List[CorrelatedEvent]) -> None:
        """
        Re-evaluate every active openflow block against this cycle's
        correlated traffic. A block is released once its flow's pps has
        stayed below UNBLOCK_RATIO of the triggering threshold for
        UNBLOCK_CONFIRM_CYCLES consecutive cycles — i.e. once the
        controller no longer "feels" the attack, confirmed rather than
        on a single quiet sample.
        """
        if not self._active_blocks:
            return

        by_dst = {c.dst_ip: c for c in correlated}

        for key in list(self._active_blocks):
            src_ip, dst_ip, dst_port, protocol = key

            correlated_event = by_dst.get(dst_ip)
            pps = 0.0
            if correlated_event:
                pps = sum(
                    e.pps for e in correlated_event.events
                    if (src_ip == "*" or e.src_ip == src_ip)
                    and e.protocol == protocol
                    and e.dst_port == dst_port
                )

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
