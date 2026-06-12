from dataclasses import dataclass

@dataclass
class FlowEvent:
    src_ip: str
    dst_ip: str
    protocol: int
    packets: int
    bytes: int
    flow_id: str


@dataclass
class DetectionEvent:
    detector: str
    src_ip: str
    score: float
