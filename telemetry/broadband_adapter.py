from typing import List

from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter


class BroadbandAdapter(DomainAdapter):
    """
    Telemetry adapter for the Fixed Broadband Domain (BNG / OLT).

    Production integration points:
    - Telemetry : NETCONF/YANG get-data on ietf-interfaces or
                  vendor model (e.g. Cisco-IOS-XE-mpls-fwd-oper)
                  Alternatively: gRPC dial-out streaming telemetry
    - Mitigation: NETCONF edit-config to install an ACL or
                  PPPoE subscriber rate-limit on the BNG

    Currently a stub — returns no events until the BNG endpoint is wired up.
    """

    domain_name = "broadband"

    def __init__(self, bng_host: str = None, netconf_port: int = 830):
        self.bng_host = bng_host
        self.netconf_port = netconf_port

    def is_connected(self) -> bool:
        # TODO: open a NETCONF session and verify capabilities
        return False

    def collect(self) -> List[TelemetryEvent]:
        # TODO: NETCONF get-data → parse interface/subscriber counters
        #       → return TelemetryEvent list
        return []

    def apply_mitigation(self, action: MitigationAction) -> bool:
        # TODO: NETCONF edit-config to apply ACL / rate-limit on BNG
        print(f"[BROADBAND] {action.action} {action.src_ip} → BNG (stub)")
        return False
