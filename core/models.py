from dataclasses import dataclass, field
from datetime import datetime
from typing import List


# ---------------------------------------------------------------------------
# Legacy — kept for backward compatibility
# ---------------------------------------------------------------------------

class FlowEvent:

    def __init__(self, src_ip, dst_ip, protocol, packets, bytes, flow_id):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.packets = packets
        self.bytes = bytes
        self.flow_id = flow_id


# ---------------------------------------------------------------------------
# Stage 1 — Telemetry Collection
# ---------------------------------------------------------------------------

@dataclass
class TelemetryEvent:
    """
    Normalized telemetry event produced by any domain adapter.
    Fed into the Multidomain Correlation layer.

    domain    : "openflow" | "mobile" | "broadband" | "enterprise" | "bgp"
    device_id : switch DPID, BNG hostname, router ID, etc.
    protocol  : "TCP" | "UDP" | "ICMP" | "IP"
    pps       : packets per second
    bps       : bytes per second
    flags     : optional protocol flags, e.g. {"SYN": True}
    """
    domain: str
    device_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    pps: float
    bps: float
    flags: dict = field(default_factory=dict)
    timestamp: float = field(
        default_factory=lambda: datetime.now().timestamp()
    )


# ---------------------------------------------------------------------------
# Stage 2 — Multidomain Correlation
# ---------------------------------------------------------------------------

@dataclass
class CorrelatedEvent:
    """
    Output of the Multidomain Correlation layer.
    Groups TelemetryEvents from all domains that target the same destination.

    domains : list of domain names contributing (e.g. ["openflow", "bgp"])
    events  : raw TelemetryEvent objects that were aggregated
    """
    dst_ip: str
    total_pps: float
    total_bps: float
    domains: List[str]
    events: List[TelemetryEvent]
    timestamp: float = field(
        default_factory=lambda: datetime.now().timestamp()
    )


# ---------------------------------------------------------------------------
# Stage 3 — DDoS Detection Engine
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """
    Output of the DDoS Detection Engine.
    Produced when a CorrelatedEvent exceeds attack thresholds.

    attack_type : "SYN_FLOOD" | "UDP_FLOOD" | "ICMP_FLOOD" | "LOW_SLOW" | "DDOS_DISTRIBUTED"
    score       : raw metric ratio (observed / threshold)
    confidence  : 0.0–1.0, boosted when attack spans multiple domains
    sources     : distinct source IPs contributing — only populated for
                  DDOS_DISTRIBUTED, where src_ip is "*" (no single attacker)
    """
    domain: str
    device_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    attack_type: str
    score: float
    confidence: float
    sources: List[str] = field(default_factory=list)
    timestamp: float = field(
        default_factory=lambda: datetime.now().timestamp()
    )


# ---------------------------------------------------------------------------
# Stage 5 — Orchestration and Control
# ---------------------------------------------------------------------------

@dataclass
class MitigationAction:
    """
    Command issued by the Orchestration layer to a domain's mitigation backend.

    action   : "block" | "rate_limit" | "bgp_blackhole"
    duration : how long the rule should stay active (seconds)
    dst_ip/dst_port/protocol : L4 5-tuple fields the mitigation backend
                               should match on (block by exact flow, not
                               just by source IP)
    sources     : when src_ip == "*" (distributed attack), the distinct
                  source IPs seen — used to clean up the per-source
                  forwarding rules that were letting them through
    attack_type : the DetectionResult.attack_type that triggered this
                  action — carried through purely for descriptive logging
    """
    domain: str
    device_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    action: str
    duration: int = 60
    sources: List[str] = field(default_factory=list)
    attack_type: str = ""
