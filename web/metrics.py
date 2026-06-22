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

# Per-switch traffic broken down by protocol (TCP/UDP/ICMP/IP), from the
# same TelemetryEvents the detection pipeline already classifies — not
# tied to a physical port, since flow-stats-derived events don't carry
# in_port (LearningSwitch's L3-only match doesn't either).
SWITCH_PROTOCOL_BYTE_RATE = Gauge(
    "sdn_switch_protocol_byte_rate",
    "Flow byte rate per switch, by protocol (B/s)",
    ["dpid", "protocol"],
)
SWITCH_PROTOCOL_PACKET_RATE = Gauge(
    "sdn_switch_protocol_packet_rate",
    "Flow packet rate per switch, by protocol (pkt/s)",
    ["dpid", "protocol"],
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

# Rate of the traffic that triggered the most recent detection/mitigation
# for each attack_type — a gauge (last value), not a counter, since "rate"
# isn't cumulative. LOW_SLOW detections leave these at 0 (flow-count based,
# no pps/bps concept).
ATTACK_BYTE_RATE = Gauge(
    "ddos_attack_byte_rate", "Byte rate of the detected attack, by type (B/s)",
    ["attack_type", "domain"],
)
ATTACK_PACKET_RATE = Gauge(
    "ddos_attack_packet_rate", "Packet rate of the detected attack, by type (pkt/s)",
    ["attack_type", "domain"],
)
MITIGATION_BYTE_RATE = Gauge(
    "ddos_mitigation_byte_rate", "Byte rate of the mitigated traffic, by type (B/s)",
    ["attack_type", "action"],
)
MITIGATION_PACKET_RATE = Gauge(
    "ddos_mitigation_packet_rate", "Packet rate of the mitigated traffic, by type (pkt/s)",
    ["attack_type", "action"],
)

# For "top N attacker/victim" panels — only incremented on a NEWLY enforced
# block (see orchestration/controller.py's _dispatch), not every cycle an
# already-active block gets re-evaluated, so this counts distinct block
# events, not "how many cycles has this attack lasted".
BLOCKS_BY_SOURCE = Counter(
    "ddos_blocks_by_source_total", "Blocks enforced, by attacker source IP", ["src_ip"]
)
BLOCKS_BY_DESTINATION = Counter(
    "ddos_blocks_by_destination_total", "Blocks enforced, by victim destination IP", ["dst_ip"]
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


def update_switch_protocol_stats(dpid, protocol, byte_rate, packet_rate):
    labels = {"dpid": str(dpid), "protocol": protocol}
    SWITCH_PROTOCOL_BYTE_RATE.labels(**labels).set(byte_rate)
    SWITCH_PROTOCOL_PACKET_RATE.labels(**labels).set(packet_rate)


def record_detection(attack_type, domain):
    ATTACKS_DETECTED.labels(attack_type=attack_type, domain=domain).inc()


def record_attack_rate(attack_type, domain, pps, bps):
    ATTACK_BYTE_RATE.labels(attack_type=attack_type, domain=domain).set(bps)
    ATTACK_PACKET_RATE.labels(attack_type=attack_type, domain=domain).set(pps)


def record_mitigation(attack_type, action, domain):
    MITIGATIONS_APPLIED.labels(attack_type=attack_type, action=action, domain=domain).inc()


def record_mitigation_rate(attack_type, action, pps, bps):
    MITIGATION_BYTE_RATE.labels(attack_type=attack_type, action=action).set(bps)
    MITIGATION_PACKET_RATE.labels(attack_type=attack_type, action=action).set(pps)


def record_block_endpoints(src_ip, dst_ip):
    BLOCKS_BY_SOURCE.labels(src_ip=src_ip).inc()
    BLOCKS_BY_DESTINATION.labels(dst_ip=dst_ip).inc()


def set_active_blocks(count):
    ACTIVE_BLOCKS.set(count)
