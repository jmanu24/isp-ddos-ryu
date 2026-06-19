"""
Prometheus metrics for the centralized SDN controller.

Traffic and pipeline events are no longer dumped to the console — they're
exported here for Grafana (via Prometheus scraping GET /metrics, see
web/api.py) to visualize instead.
"""

from prometheus_client import Counter, Gauge

# ── Traffic — per switch / port, from periodic OpenFlow stats polling ──────

SWITCH_BYTE_RATE = Gauge(
    "sdn_switch_byte_rate", "Aggregate flow byte rate per switch (B/s)", ["dpid"]
)
SWITCH_PACKET_RATE = Gauge(
    "sdn_switch_packet_rate", "Aggregate flow packet rate per switch (pkt/s)", ["dpid"]
)

PORT_RX_BYTES = Gauge(
    "sdn_port_rx_bytes_total", "Cumulative RX bytes per switch port", ["dpid", "port"]
)
PORT_TX_BYTES = Gauge(
    "sdn_port_tx_bytes_total", "Cumulative TX bytes per switch port", ["dpid", "port"]
)
PORT_RX_PACKETS = Gauge(
    "sdn_port_rx_packets_total", "Cumulative RX packets per switch port", ["dpid", "port"]
)
PORT_TX_PACKETS = Gauge(
    "sdn_port_tx_packets_total", "Cumulative TX packets per switch port", ["dpid", "port"]
)
PORT_RX_DROPPED = Gauge(
    "sdn_port_rx_dropped_total", "Cumulative RX drops per switch port", ["dpid", "port"]
)
PORT_TX_DROPPED = Gauge(
    "sdn_port_tx_dropped_total", "Cumulative TX drops per switch port", ["dpid", "port"]
)

# ── DDoS pipeline — detections and mitigations ──────────────────────────────

ATTACKS_DETECTED = Counter(
    "ddos_attacks_detected_total",
    "Attacks detected by the DDoS Detection Engine",
    ["attack_type", "domain"],
)
MITIGATIONS_APPLIED = Counter(
    "ddos_mitigations_applied_total",
    "Mitigation actions dispatched by the Orchestration layer",
    ["attack_type", "action", "domain"],
)
ACTIVE_BLOCKS = Gauge(
    "ddos_active_blocks", "Currently active mitigation blocks (openflow domain)"
)


def update_switch_stats(dpid, byte_rate, packet_rate):
    SWITCH_BYTE_RATE.labels(dpid=str(dpid)).set(byte_rate)
    SWITCH_PACKET_RATE.labels(dpid=str(dpid)).set(packet_rate)


def update_port_stats(dpid, port_no, stat):
    labels = {"dpid": str(dpid), "port": str(port_no)}
    PORT_RX_BYTES.labels(**labels).set(stat.rx_bytes)
    PORT_TX_BYTES.labels(**labels).set(stat.tx_bytes)
    PORT_RX_PACKETS.labels(**labels).set(stat.rx_packets)
    PORT_TX_PACKETS.labels(**labels).set(stat.tx_packets)
    PORT_RX_DROPPED.labels(**labels).set(stat.rx_dropped)
    PORT_TX_DROPPED.labels(**labels).set(stat.tx_dropped)


def record_detection(attack_type, domain):
    ATTACKS_DETECTED.labels(attack_type=attack_type, domain=domain).inc()


def record_mitigation(attack_type, action, domain):
    MITIGATIONS_APPLIED.labels(attack_type=attack_type, action=action, domain=domain).inc()


def set_active_blocks(count):
    ACTIVE_BLOCKS.set(count)
