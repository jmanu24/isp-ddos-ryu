from typing import Dict, List

from core.models import DetectionResult, MitigationAction
from decision.engine import DecisionEngine, Decision
from telemetry.base import DomainAdapter
from mitigation.openflow_mitigator import OpenFlowMitigator


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
    """

    def __init__(self, adapters: List[DomainAdapter]):
        # Index adapters by domain name for O(1) dispatch
        self._adapters: Dict[str, DomainAdapter] = {
            a.domain_name: a for a in adapters
        }
        self._decision_engine = DecisionEngine()
        self.of_mitigator = OpenFlowMitigator()

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
            return

        adapter = self._adapters.get(action.domain)

        if adapter:
            adapter.apply_mitigation(action)
        else:
            print(
                f"[ORCHESTRATION] No adapter registered "
                f"for domain '{action.domain}'"
            )
