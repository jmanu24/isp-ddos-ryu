from typing import Dict, Set

from core.models import MitigationAction
from mitigation.base import MitigationAdapter


class OpenFlowMitigator(MitigationAdapter):
    """
    Mitigation backend for the OpenFlow / SDN domain.

    Installs high-priority drop rules on all registered Ryu datapaths
    to block traffic originating from an attacking source IP.

    The controller registers/deregisters datapaths as switches connect
    and disconnect; this mitigator then applies rules to every active
    datapath at once so the block is network-wide within the SDN domain.
    """

    # OpenFlow flow rule priority for drop rules (higher than forwarding rules)
    DROP_PRIORITY = 100

    def __init__(self):
        self._blocked: Set[str] = set()
        self._datapaths: Dict[int, object] = {}   # dpid -> Ryu datapath

    # ------------------------------------------------------------------
    # Datapath lifecycle — called from the Ryu controller
    # ------------------------------------------------------------------

    def register(self, datapath) -> None:
        """Register a new switch datapath."""
        self._datapaths[datapath.id] = datapath

    def deregister(self, dpid: int) -> None:
        """Remove a disconnected switch datapath."""
        self._datapaths.pop(dpid, None)

    # ------------------------------------------------------------------
    # MitigationAdapter interface
    # ------------------------------------------------------------------

    def apply(self, action: MitigationAction) -> bool:
        if action.action == "block":
            self.block(action.src_ip)
            return True
        return False

    # ------------------------------------------------------------------
    # Public mitigation methods
    # ------------------------------------------------------------------

    def block(self, src_ip: str) -> None:
        """
        Install a drop rule for src_ip on all active OpenFlow switches.
        Idempotent — calling block() on an already-blocked IP is a no-op.
        """
        if src_ip in self._blocked:
            return

        self._blocked.add(src_ip)

        for datapath in self._datapaths.values():
            self._install_drop_rule(datapath, src_ip)

        print(
            f"[OF_MITIGATOR] Blocked {src_ip} "
            f"on {len(self._datapaths)} switch(es)"
        )

    def unblock(self, src_ip: str) -> None:
        """
        Remove the drop rule for src_ip from all active switches.
        """
        if src_ip not in self._blocked:
            return

        self._blocked.discard(src_ip)

        for datapath in self._datapaths.values():
            self._delete_drop_rule(datapath, src_ip)

        print(f"[OF_MITIGATOR] Unblocked {src_ip}")

    # ------------------------------------------------------------------
    # Internal OpenFlow helpers
    # ------------------------------------------------------------------

    def _install_drop_rule(self, datapath, src_ip: str) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        inst = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=self.DROP_PRIORITY,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    def _delete_drop_rule(self, datapath, src_ip: str) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            priority=self.DROP_PRIORITY,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        datapath.send_msg(mod)
