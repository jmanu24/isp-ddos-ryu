from typing import List

from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter


class BGPPeeringAdapter(DomainAdapter):
    """
    Telemetry adapter for the BGP Peering Domain (Border Router / IGR).

    Production integration points:
    - Telemetry : NetFlow/sFlow from the border router,
                  or BGP Monitoring Protocol (BMP, RFC 7854)
    - Mitigation: BGP Blackhole Community announcement (RFC 7999)
                  via ExaBGP, GoBGP, or a NETCONF RPC on the BR

    Currently a stub — returns no events until the router endpoint is wired up.
    """

    domain_name = "bgp"

    # RFC 7999 well-known blackhole community
    DEFAULT_BLACKHOLE_COMMUNITY = "65535:666"

    def __init__(
        self,
        router_host: str = None,
        bgp_community: str = DEFAULT_BLACKHOLE_COMMUNITY
    ):
        self.router_host = router_host
        self.bgp_community = bgp_community

    def is_connected(self) -> bool:
        # TODO: verify BMP session or ExaBGP API reachability
        return False

    def collect(self) -> List[TelemetryEvent]:
        # TODO: parse BMP RIB-IN updates or sFlow datagrams
        #       → return TelemetryEvent list
        return []

    def apply_mitigation(self, action: MitigationAction) -> bool:
        # TODO: announce RTBH route for action.src_ip with bgp_community
        #       via ExaBGP REST API or GoBGP gRPC
        print(
            f"[BGP] Blackhole {action.src_ip} "
            f"community={self.bgp_community} (stub)"
        )
        return False
