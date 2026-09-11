"""
mitigation/peering_backend.py — BGP FlowSpec speaker for the Peering domain.

Talks to a locally running `exabgp` process, which holds the actual BGP
session to r1's FRR (bgpd + zebra). exabgp's own config wires an `api`
process section that reads commands -- one per line, ExaBGP's own
route-announcement syntax -- from a named pipe (FIFO); this module only
ever writes to that FIFO. It does not implement BGP itself.

CAPABILITY STATUS -- read before trusting a True return here: this
announces a FlowSpec discard route. Whether r1's FRR actually translates
a received FlowSpec route into a real nftables/iptables rule is
UNVERIFIED (see docs/peering-plan.md §2, the FlowSpec dataplane spike).
apply()/announce()/withdraw() report success based on the FIFO write
succeeding, which only proves the announcement was handed to exabgp --
NOT that traffic is actually being dropped. Per implementation-design.md
§5's state machine, this is at most DISPATCHED/ACCEPTED, never APPLIED
or VERIFIED; do not report it to the UI/logs as a confirmed block.
"""
import logging
import os
import time
from typing import Dict, Optional, Tuple

import config.settings as settings
from core.log_format import log_line
from core.models import MitigationAction
from mitigation.base import MitigationAdapter

_PROTO_NAMES = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp"}


class PeeringBackend(MitigationAdapter):
    """
    Announces/withdraws BGP FlowSpec discard routes via exabgp's FIFO API.

    Tracks active routes by (dst_ip, dst_port, protocol) for idempotency
    and to support unblock the same way OpenFlowMitigator does for the
    Enterprise domain.
    """

    def __init__(
        self,
        fifo_path: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
        clock=time.time,
    ):
        self.fifo_path = fifo_path or settings.PEERING_EXABGP_FIFO
        self.logger = logger or logging.getLogger(__name__)
        self.clock = clock
        self._active: Dict[Tuple[str, int, str], float] = {}

    # ------------------------------------------------------------------
    # MitigationAdapter interface
    # ------------------------------------------------------------------

    def apply(self, action: MitigationAction) -> bool:
        if action.action == "bgp_flowspec_discard":
            return self.announce(action.dst_ip, action.dst_port, action.protocol)
        if action.action == "unblock":
            return self.withdraw(action.dst_ip, action.dst_port, action.protocol)
        return False

    # ------------------------------------------------------------------
    # Public mitigation methods
    # ------------------------------------------------------------------

    def announce(self, dst_ip: str, dst_port: int, protocol: str) -> bool:
        """Idempotent -- announcing an already-active route is a no-op success."""
        key = (dst_ip, dst_port, protocol)
        if key in self._active:
            return True

        if not self._send(self._flow_command("announce", dst_ip, dst_port, protocol)):
            return False

        self._active[key] = self.clock()
        self.logger.info(log_line(
            "bgp", "MITIGATION", "FLOWSPEC_ANNOUNCED",
            f"destination={dst_ip}:{dst_port}/{protocol}",
        ))
        return True

    def withdraw(self, dst_ip: str, dst_port: int, protocol: str) -> bool:
        key = (dst_ip, dst_port, protocol)
        if key not in self._active:
            return False

        ok = self._send(self._flow_command("withdraw", dst_ip, dst_port, protocol))
        self._active.pop(key, None)
        if ok:
            self.logger.info(log_line(
                "bgp", "MITIGATION", "FLOWSPEC_WITHDRAWN",
                f"destination={dst_ip}:{dst_port}/{protocol}",
            ))
        return ok

    def is_connected(self) -> bool:
        """
        True only if the FIFO exists -- i.e. exabgp was configured with
        the expected `api` process section and created it. This does NOT
        confirm the BGP session to r1 is established.
        """
        return bool(self.fifo_path) and os.path.exists(self.fifo_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _flow_command(verb: str, dst_ip: str, dst_port: int, protocol: str) -> str:
        """
        Build one ExaBGP flow-route command line. dst_ip is announced as
        a /32 host route -- this backend only ever discards traffic
        toward a single destination IP (the attack target), never a
        broader prefix; RTBH-style whole-prefix blackholing is out of
        scope for this action (see docs/peering-plan.md §1).
        """
        match = [f"destination {dst_ip}/32;"]
        proto = _PROTO_NAMES.get(protocol)
        if proto:
            match.append(f"protocol {proto};")
        if dst_port:
            match.append(f"destination-port ={dst_port};")

        match_body = " ".join(match)
        return f"{verb} flow route {{ match {{ {match_body} }} then {{ discard; }} }}"

    def _send(self, command: str) -> bool:
        if not self.fifo_path:
            self.logger.warning("PEERING_EXABGP_FIFO not configured -- cannot send: %s", command)
            return False
        try:
            # O_NONBLOCK so this never hangs the calling thread if exabgp
            # isn't reading the FIFO (e.g. the process is down) -- a plain
            # open() on a FIFO with no reader blocks forever otherwise.
            fd = os.open(self.fifo_path, os.O_WRONLY | os.O_NONBLOCK)
            try:
                os.write(fd, (command + "\n").encode())
            finally:
                os.close(fd)
            return True
        except OSError as exc:
            self.logger.warning("Failed writing to exabgp FIFO %s: %s", self.fifo_path, exc)
            return False
