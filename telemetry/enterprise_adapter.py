from typing import List

from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter


class EnterpriseAdapter(DomainAdapter):
    """
    Telemetry adapter for the Enterprise Services Domain (PE router).

    Production integration points:
    - Telemetry : NETCONF/YANG, gRPC dial-out streaming telemetry,
                  or SNMP from the Provider Edge router
    - Mitigation: NETCONF RPC to apply an inbound ACL on the PE,
                  or inject a BGP FlowSpec route (RFC 5575)

    Currently a stub — returns no events until the PE endpoint is wired up.
    """

    domain_name = "enterprise"

    def __init__(self, pe_host: str = None):
        self.pe_host = pe_host

    def is_connected(self) -> bool:
        # TODO: verify NETCONF/gRPC connectivity to PE
        return False

    def collect(self) -> List[TelemetryEvent]:
        # TODO: poll PE via NETCONF or gRPC streaming telemetry
        #       → parse VRF/interface counters → return TelemetryEvent list
        return []

    def apply_mitigation(self, action: MitigationAction) -> bool:
        # TODO: inject BGP FlowSpec route or apply inbound ACL via NETCONF
        print(f"[ENTERPRISE] {action.action} {action.src_ip} → PE (stub)")
        return False
