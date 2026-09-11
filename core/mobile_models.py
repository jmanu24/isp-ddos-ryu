"""Real mobile observations: traffic counters and radio context stay separate."""
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class FlowObservation:
    observation_id: str
    source: str
    network_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_count: int
    packets_count: int
    start: float
    end: float


@dataclass(frozen=True)
class UeSessionBinding:
    network_id: str
    supi: str
    session_id: str
    ue_ip: str
    valid_from: float
    source: str
    valid_until: Optional[float] = None
    ran_source: Optional[str] = None
    node_id: Optional[str] = None
    ue_id_type: Optional[str] = None
    ue_id: Optional[str] = None
    cell_id: Optional[str] = None


@dataclass(frozen=True)
class KpmObservation:
    source: str
    node_id: str
    metric: str
    value: Optional[float]
    unit: str
    timestamp: float
    scope: str = "node"
    status: str = "VALID"
    reliable: bool = True
    ue_id_type: Optional[str] = None
    ue_id: Optional[str] = None
    cell_id: Optional[str] = None
