from time import time

from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

import config.settings as settings


class DDoSCollector:
    """
    Aggregates packet-in traffic per destination (dst_ip, dst_port, protocol)
    rather than per full (src, dst, port, protocol) flow.

    Keying by destination only — instead of including src_ip in the key —
    matters for spoofed-source / distributed floods: a single-source flood
    repeats the same key across packets, so a per-flow key works fine, but a
    spoofed attack uses a different source on (almost) every packet, so a
    src-inclusive key would never see the same key twice and could never
    compute a rate. Aggregating by destination, with a per-source packet
    breakdown inside that window, captures both cases: a dominant single
    source (low entropy) or many evenly-spread sources (high entropy).
    """

    def __init__(self):
        self.stats = {}
        # (src_ip, dst_ip) -> {"ports": {src_port, ...}, "last_update": t}.
        # Tracks how many distinct source ports one host has used toward
        # another — a single-source Slowloris-style attack opens many real
        # connections (each its own src_port) to the same destination, all
        # of which collapse into ONE L3 forwarding rule (LearningSwitch
        # matches on ipv4_src/ipv4_dst only), so OpenFlow flow stats can
        # never show them as separate flows. This is the only place that
        # ever sees each connection's own src_port — packet-in, on
        # whichever packets still reach it.
        self._connection_ports = {}

    def process_packet(self, msg):

        pkt = packet.Packet(msg.data)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if not ip_pkt:
            return None

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        if tcp_pkt and (tcp_pkt.bits & tcp.TCP_RST):
            # A victim sends RST in plain response to an unwanted/closed-
            # port SYN — that's it defending itself, not a second attack.
            # hping3 (and similar floods) vary the source port per probe,
            # so each reply burst lands on a different ephemeral dst_port
            # and gets misread as its own short-lived SYN_FLOOD otherwise.
            return None

        protocol = "IP"
        dst_port = 0

        if tcp_pkt:
            # Bare SYN (no ACK) is a connection attempt — the actual
            # signature of a SYN flood. Once the handshake completes,
            # later packets carry ACK and are just normal (if slow)
            # traffic on an established connection: e.g. a Slowloris-
            # style attack opens real connections and then trickles data
            # for a long time, which should surface as LOW_SLOW (flow
            # count, low bytes, old age) rather than keep tripping
            # SYN_FLOOD on every cycle just because it's TCP.
            is_bare_syn = (tcp_pkt.bits & tcp.TCP_SYN) and not (tcp_pkt.bits & tcp.TCP_ACK)
            protocol = "TCP_SYN" if is_bare_syn else "TCP"
            dst_port = tcp_pkt.dst_port

        elif udp_pkt:
            protocol = "UDP"
            dst_port = udp_pkt.dst_port

        elif ip_pkt.proto == 1:
            protocol = "ICMP"

        key = (
            ip_pkt.dst,
            dst_port,
            protocol
        )

        now = time()

        if tcp_pkt or udp_pkt:
            src_port = tcp_pkt.src_port if tcp_pkt else udp_pkt.src_port
            conn_key = (ip_pkt.src, ip_pkt.dst)
            conn_entry = self._connection_ports.setdefault(
                conn_key,
                {"ports": set(), "last_update": now, "dst_port": 0, "protocol": "IP", "new_connections": 0},
            )

            if src_port not in conn_entry["ports"]:
                # A genuinely new connection (never-seen source port) —
                # cumulative count, for a "new connections/sec" Grafana
                # panel via rate(). This is also the closest thing this
                # L3-only architecture has to "connections per second":
                # an already-open connection's ongoing packets are
                # invisible once cached, until the next periodic
                # VALIDATED_FLOW_HARD_TIMEOUT-forced refresh, so there's
                # no separate "total connection activity" signal to track.
                conn_entry["new_connections"] += 1

            conn_entry["ports"].add(src_port)
            conn_entry["last_update"] = now
            # Remember the targeted port/protocol too, so a mitigation
            # block can be scoped to the exact L4 flow instead of every
            # port this attacker happens to touch. Slowloris-style attacks
            # target one fixed port — last-seen is fine. "TCP_SYN" is
            # collapsed to "TCP" here since this is about the established
            # connection, not the handshake.
            conn_entry["dst_port"] = dst_port
            conn_entry["protocol"] = "TCP" if protocol == "TCP_SYN" else protocol

        entry = self.stats.get(key)

        if entry is None:
            entry = {
                "src_packets": {},
                "bytes": 0,
                "packets": 0,
                "timestamp": now
            }
            self.stats[key] = entry

        entry["src_packets"][ip_pkt.src] = entry["src_packets"].get(ip_pkt.src, 0) + 1
        entry["packets"] += 1
        entry["bytes"] += len(msg.data)

        delta = now - entry["timestamp"]

        if delta < 1:
            return None

        result = {
            "dst_ip": key[0],
            "dst_port": key[1],
            "protocol": key[2],
            "pps": entry["packets"] / delta,
            "bps": entry["bytes"] / delta,
            "src_pps": {
                src: count / delta
                for src, count in entry["src_packets"].items()
            },
        }

        entry["src_packets"] = {}
        entry["packets"] = 0
        entry["bytes"] = 0
        entry["timestamp"] = now

        return result

    def get_connection_port_counts(self):
        """
        (src_ip, dst_ip) -> {"count": distinct source ports seen toward
        that destination recently (concurrent connections), "dst_port":
        last-seen targeted port, "protocol": "TCP"|"UDP", "new_connections":
        cumulative count of distinct ports ever seen for this pair (for a
        rate()-based "new connections/sec" panel — this value only grows,
        never resets, for as long as the pair stays alive). Ports
        accumulate for as long as that pair keeps appearing in packet-in
        (which it will, periodically, even once cached — see
        VALIDATED_FLOW_HARD_TIMEOUT forcing re-classification); an entry
        is forgotten once that pair hasn't been seen at all for
        LOW_SLOW_PORT_IDLE_TTL seconds, so a stale attack from a while
        ago doesn't linger forever.
        """
        now = time()
        counts = {}

        for conn_key in list(self._connection_ports):
            entry = self._connection_ports[conn_key]

            if now - entry["last_update"] > settings.LOW_SLOW_PORT_IDLE_TTL:
                del self._connection_ports[conn_key]
                continue

            counts[conn_key] = {
                "count": len(entry["ports"]),
                "dst_port": entry["dst_port"],
                "protocol": entry["protocol"],
                "new_connections": entry["new_connections"],
            }

        return counts
