"""
bng_config.py — builds the BNGBlaster JSON test config for the Fixed
Broadband Domain attack simulator (simulation/bng_traffic_simulator.py).

BNGBlaster has no "attack mode" -- every scenario here is a deliberate
combination of its own real features:

  TCP SYN Flood          : one PPPoE/IPoE session, one `streams` entry
                           with raw-tcp:true (bare TCP framing instead
                           of UDP-like) at a high pps -- a single
                           attacker.
  UDP Flood              : one session, one `streams` entry (default
                           UDP-like framing) at a high pps/bps.
  ICMP Flood             : one session, BNGBlaster's own `icmp-client`
                           block (https://rtbrick.github.io/bngblaster/icmp.html)
                           -- a real ICMP echo-request generator, not a
                           `streams` entry (BNGBlaster's stream types are
                           ipv4/ipv6/ipv6pd with UDP-like or raw-tcp L4
                           framing only; ICMP is its own feature) -- at a
                           small `interval` for a high request rate.
  Distributed TCP SYN    : N (>= settings.DIST_MIN_SOURCES) sessions,
  Flood                    each replicating the SAME raw-tcp stream
                           definition at a modest per-session pps -- the
                           aggregate across many distinct subscriber
                           sessions is what crosses SYN_THRESHOLD, not
                           any single one (near-equal per-session rate
                           keeps source-IP entropy high, the signature
                           DDoSDetectionEngine's distributed check needs).
  Low and Slow           : N (>= settings.LOW_SLOW_MOBILE_MIN_SOURCES)
                           sessions, each holding a deliberately tiny,
                           continuous raw-tcp stream (no flood-volume
                           rate by design -- this is a Slowloris-style
                           "many quiet sources at once", not a burst) for
                           the whole run.

Each scenario's `streams`/`icmp-client` definition is replicated
automatically across every PPPoE/IPoE session BNGBlaster creates
(config["sessions"]["count"]) -- so the "N sessions" above is just
sessions.count, not N separate stream definitions.
"""

from typing import Optional

ATTACK_STREAM_GROUP_ID = 100
ATTACK_ICMP_GROUP_ID = 200
NORMAL_STREAM_GROUP_ID = 1

SCENARIOS = ("syn_flood", "udp_flood", "icmp_flood", "distributed_syn_flood", "low_and_slow")

# Per-scenario (session_count, per-session rate, attack_kind). pps values
# are picked the same way ul_traffic_simulator.py's scenario_* functions
# pick attack_mbps: comfortably past config/settings.py's threshold for
# the matching attack_type, not tuned against anything BNGBlaster-side
# (BNGBlaster doesn't classify traffic -- detection happens downstream in
# DDoSDetectionEngine once these counters reach a TelemetryEvent).
#
# config/settings.py thresholds each is tuned against:
#   SYN_THRESHOLD=10 pps, UDP_THRESHOLD=200 pps, ICMP_THRESHOLD=150 pps
#   DIST_MIN_SOURCES=5, DIST_ENTROPY_THRESHOLD=0.7 (near-equal per-source rate)
#   LOW_SLOW_MOBILE_MAX_PPS=8.0 (ceiling), LOW_SLOW_MOBILE_MIN_SOURCES=5
_SCENARIO_PARAMS = {
    # single attacker, well past SYN_THRESHOLD=10
    "syn_flood":             dict(sessions=1, pps=200.0, kind="stream", protocol="TCP_SYN", dst_port=443, raw_tcp=True),
    # single attacker, well past UDP_THRESHOLD=200
    "udp_flood":             dict(sessions=1, pps=5000.0, kind="stream", protocol="UDP", dst_port=0, raw_tcp=False),
    # single attacker, icmp-client interval sized for ~300 req/s (well past ICMP_THRESHOLD=150)
    "icmp_flood":            dict(sessions=1, interval=0.0033, kind="icmp", protocol="ICMP", dst_port=0),
    # 8 sessions (>= DIST_MIN_SOURCES=5), 5 pps each -> ~40 pps aggregate
    # (> SYN_THRESHOLD=10), uniform per-session rate -> high entropy
    "distributed_syn_flood": dict(sessions=8, pps=5.0, kind="stream", protocol="TCP_SYN", dst_port=443, raw_tcp=True),
    # 8 sessions (>= LOW_SLOW_MOBILE_MIN_SOURCES=5), each well under
    # LOW_SLOW_MOBILE_MAX_PPS=8.0 -- deliberately not a flood
    "low_and_slow":          dict(sessions=8, pps=0.05, kind="stream", protocol="TCP_SYN", dst_port=443, raw_tcp=True),
}


def _base_config(
    access_interface: str,
    network_interface: str,
    session_count: int,
    network_ip: str,
    network_gateway: str,
) -> dict:
    return {
        "interfaces": {
            "network": [{
                "interface": network_interface,
                "address": network_ip,
                "gateway": network_gateway,
            }],
            "access": [{
                "interface": access_interface,
                "type": "ipoe",
                # 0/0 = untagged (BNGBlaster's own default) -- per-VLAN
                # tagging (1..session_count) was this script's original,
                # unnecessary choice, and a real run showed why it's the
                # wrong one here: deploy/setup_bng_netns.sh's dnsmasq
                # listens on veth-a-peer with no 802.1Q sub-interfaces,
                # so VLAN-tagged DHCPDISCOVER frames likely never reached
                # its plain UDP socket at all (dhcp-tx-discover kept
                # incrementing, dhcp-rx-offer stayed 0 forever). IPoE
                # sessions don't need VLANs to be distinct -- BNGBlaster
                # already gives each one its own MAC (confirmed: session 1
                # got "02:00:00:00:00:01" on a real run) -- so untagged
                # avoids the whole VLAN/dnsmasq mismatch instead of fixing
                # it by adding VLAN sub-interfaces on the peer side.
                "outer-vlan-min": 0,
                "outer-vlan-max": 0,
            }],
        },
        "sessions": {
            "count": session_count,
            "start-rate": min(400, max(1, session_count)),
        },
        "dhcp": {"enable": True},
        "streams": [],
    }


def _normal_stream(network_interface: str, target_ip: str) -> dict:
    """Low, steady baseline traffic every session sends -- the
    fixed-broadband-domain equivalent of ul_traffic_simulator.py's
    UE.baseline_mbps, so an attack stream visibly stands out against a
    non-zero floor instead of against silence."""
    return {
        "name": "baseline",
        "stream-group-id": NORMAL_STREAM_GROUP_ID,
        "type": "ipv4",
        "direction": "upstream",
        "autostart": True,
        "network-interface": network_interface,
        "destination-ipv4-address": target_ip,
        "destination-port": 80,
        "pps": 2.0,
        "length": 256,
    }


def build_scenario(
    scenario: str,
    target_ip: str,
    access_interface: str = "veth-a",
    network_interface: str = "veth-n",
    network_ip: str = "10.50.0.10/24",
    network_gateway: str = "10.50.0.1",
    attack_autostart: Optional[bool] = None,
    attack_start_delay: int = 0,
) -> dict:
    """
    Returns {"config": <bngblaster JSON config>, "sessions": int,
    "attack_kind": "stream"|"icmp", "attack_group_id": int,
    "protocol": str, "dst_port": int, "autostart": bool}.

    attack_autostart: if None, defaults to True for "low_and_slow"
    (continuous-from-start by definition) and False for every other
    scenario (the orchestrator starts it explicitly at the configured
    attack tick, via the control socket -- the same role attack_window
    plays in ul_traffic_simulator.py).
    """
    if scenario not in _SCENARIO_PARAMS:
        raise ValueError(f"unknown scenario {scenario!r}, expected one of {SCENARIOS}")
    p = _SCENARIO_PARAMS[scenario]
    session_count = p["sessions"]
    autostart = attack_autostart if attack_autostart is not None else (scenario == "low_and_slow")

    cfg = _base_config(access_interface, network_interface, session_count, network_ip, network_gateway)
    cfg["streams"].append(_normal_stream(network_interface, target_ip))

    if p["kind"] == "stream":
        attack_stream = {
            "name": f"attack-{scenario}",
            "stream-group-id": ATTACK_STREAM_GROUP_ID,
            "type": "ipv4",
            "direction": "upstream",
            "autostart": autostart,
            "network-interface": network_interface,
            "destination-ipv4-address": target_ip,
            "destination-port": p["dst_port"],
            "pps": p["pps"],
            # BNGBlaster enforces 76 <= length <= 9000 (confirmed on a
            # real run: "Invalid value for stream->length (76 - 9000)")
            # -- 64 (a bare Ethernet-frame-sized guess for the raw-tcp
            # case) was below that floor.
            "length": 76 if p["raw_tcp"] else 128,
        }
        if attack_start_delay:
            attack_stream["start-delay"] = attack_start_delay
        if p["raw_tcp"]:
            attack_stream["raw-tcp"] = True
        cfg["streams"].append(attack_stream)
        attack_group_id = ATTACK_STREAM_GROUP_ID

    elif p["kind"] == "icmp":
        # icmp-client has no documented "autostart" field -- it starts
        # sending as soon as the session/network-interface is up. The
        # orchestrator controls its timing via icmp-client-start/-stop
        # on the control socket instead (assumed command names, mirroring
        # stream-start/-stop and session-start/-stop's naming convention
        # -- see bng_socket.py's docstring on verifying this on the
        # Ubuntu VM before trusting it).
        cfg["icmp-client"] = [{
            "icmp-client-group-id": ATTACK_ICMP_GROUP_ID,
            "destination-address": target_ip,
            "network-interface": network_interface,
            "interval": p["interval"],
            "count": 0,
        }]
        attack_group_id = ATTACK_ICMP_GROUP_ID

    else:
        raise AssertionError(f"unreachable: kind={p['kind']!r}")

    return {
        "config": cfg,
        "sessions": session_count,
        "attack_kind": p["kind"],
        "attack_group_id": attack_group_id,
        "protocol": p["protocol"],
        "dst_port": p["dst_port"],
        "autostart": autostart,
    }
