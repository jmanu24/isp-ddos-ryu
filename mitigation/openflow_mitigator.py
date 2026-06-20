from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import config.settings as settings
from core.models import MitigationAction
from mitigation.base import MitigationAdapter


PROTO_NUMBERS = {"TCP": 6, "UDP": 17, "ICMP": 1}


def _log(msg: str) -> None:
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}")


class OpenFlowMitigator(MitigationAdapter):
    """
    Mitigation backend for the OpenFlow / SDN domain.

    Installs high-priority drop rules to block traffic matching an
    attack's exact L4 flow — src_ip, dst_ip, protocol and dst_port —
    rather than blanket-blocking the source IP. Forwarding rules stay
    L3-only; only mitigation needs L4 precision.

    Scope:
    - Single-attacker block (src_ip != "*") with a known (dpid, in_port):
      installed on that ONE switch only, matching in_port too — the
      block sits on the switch+port closest to the attacker instead of
      the whole network.
    - Distributed attack (src_ip == "*") or unknown ingress point: falls
      back to every registered switch, matching the L4 5-tuple only —
      there's no single entry point to scope to.

    The controller registers/deregisters datapaths as switches connect
    and disconnect.
    """

    # OpenFlow flow rule priority for drop rules (higher than forwarding
    # rules). Shared with FlowCollector (config/settings.py) so it can
    # exclude these from polled flow stats.
    DROP_PRIORITY = settings.MITIGATION_DROP_PRIORITY

    # Priority LearningSwitch uses for its L3 (ipv4_src/ipv4_dst) forwarding
    # rules — needed to delete exactly those entries, not the drop rules.
    FORWARDING_PRIORITY = 10

    def __init__(self):
        # (src_ip, dst_ip, dst_port, protocol) tuples currently blocked
        self._blocked: Set[Tuple[str, str, int, str]] = set()
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
            dpid = int(action.device_id) if action.device_id.isdigit() else None
            self.block(
                action.src_ip, action.dst_ip, action.dst_port, action.protocol,
                dpid=dpid, in_port=action.in_port or None,
            )
            return True
        return False

    # ------------------------------------------------------------------
    # Public mitigation methods
    # ------------------------------------------------------------------

    def block(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        dpid: Optional[int] = None,
        in_port: Optional[int] = None,
    ) -> None:
        """
        Install an L4 drop rule (src_ip, dst_ip, protocol, dst_port).
        Idempotent — calling block() again on an already-blocked 4-tuple
        is a no-op.

        When dpid is known and this isn't a distributed ("*" src) attack,
        the rule is installed on that ONE switch only — the one closest
        to the attacker — and matches in_port too when known, instead of
        dropping the traffic network-wide.
        """
        key = (src_ip, dst_ip, dst_port, protocol)

        if key in self._blocked:
            return

        self._blocked.add(key)

        targets = self._scoped_targets(src_ip, dpid)

        for datapath in targets:
            self._install_drop_rule(
                datapath, src_ip, dst_ip, dst_port, protocol,
                in_port=in_port if datapath.id == dpid else None,
            )

        scope = (
            f"switch {dpid}" + (f" port {in_port}" if in_port else "")
            if len(targets) == 1 and dpid is not None
            else f"{len(targets)} switch(es) (network-wide)"
        )
        _log(
            f"[OF_MITIGATOR] Blocked {src_ip} -> {dst_ip}:{dst_port}/{protocol} "
            f"on {scope}"
        )

    def unblock(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> None:
        """
        Remove the drop rule for this L4 flow from every switch it could
        have been installed on (scoped or network-wide — unblock doesn't
        need to know which, it just deletes wherever it matches).
        """
        key = (src_ip, dst_ip, dst_port, protocol)

        if key not in self._blocked:
            return

        self._blocked.discard(key)

        for datapath in self._datapaths.values():
            self._delete_drop_rule(datapath, src_ip, dst_ip, dst_port, protocol)

        _log(f"[OF_MITIGATOR] Unblocked {src_ip} -> {dst_ip}:{dst_port}/{protocol}")

    def _scoped_targets(self, src_ip: str, dpid: Optional[int]) -> List[object]:
        """
        The datapath(s) a block should be installed on: just the attacker's
        nearest switch when known and meaningful, otherwise every switch.
        """
        if src_ip != "*" and dpid is not None and dpid in self._datapaths:
            return [self._datapaths[dpid]]
        return list(self._datapaths.values())

    def clear_forwarding_rules(self, dst_ip: str, sources: List[str]) -> None:
        """
        Delete the per-source L3 forwarding rules (installed by
        LearningSwitch, priority=10) that were letting these specific
        sources reach dst_ip. Used right after installing a destination-wide
        block ("*" src) for a distributed attack: that block already wins
        on priority regardless, but leaving thousands of one-shot spoofed-
        source forwarding entries around just wastes flow table space.

        Deletes with an exact (priority, match) using OFPFC_DELETE_STRICT,
        scoped per known source, so the drop rule for this same dst_ip
        (priority=100, a different match/priority) is never touched.
        """
        for datapath in self._datapaths.values():
            for src_ip in sources:
                self._delete_forwarding_rule(datapath, src_ip, dst_ip)

        _log(
            f"[OF_MITIGATOR] Cleared {len(sources)} forwarding rule(s) "
            f"toward {dst_ip} on {len(self._datapaths)} switch(es)"
        )

    # ------------------------------------------------------------------
    # Internal OpenFlow helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _l4_match_fields(src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> dict:
        fields = {"eth_type": 0x0800, "ipv4_dst": dst_ip}

        # "*" marks a distributed/spoofed-source attack — there's no single
        # attacker IP to match on, so the rule drops by destination alone.
        if src_ip and src_ip != "*":
            fields["ipv4_src"] = src_ip

        proto_num = PROTO_NUMBERS.get(protocol)
        if proto_num is None:
            return fields

        fields["ip_proto"] = proto_num

        if protocol == "TCP" and dst_port:
            fields["tcp_dst"] = dst_port
        elif protocol == "UDP" and dst_port:
            fields["udp_dst"] = dst_port

        return fields

    def _install_drop_rule(self, datapath, src_ip, dst_ip, dst_port, protocol, in_port=None) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        fields = self._l4_match_fields(src_ip, dst_ip, dst_port, protocol)
        if in_port:
            fields["in_port"] = in_port

        match = parser.OFPMatch(**fields)
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

    def _delete_drop_rule(self, datapath, src_ip, dst_ip, dst_port, protocol) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(**self._l4_match_fields(src_ip, dst_ip, dst_port, protocol))

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            priority=self.DROP_PRIORITY,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        datapath.send_msg(mod)

    def _delete_forwarding_rule(self, datapath, src_ip: str, dst_ip: str) -> None:
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            priority=self.FORWARDING_PRIORITY,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        datapath.send_msg(mod)
