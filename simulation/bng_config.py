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
                # N:1 (many sessions sharing ONE VLAN, distinguished by
                # per-session MAC only) instead of the previous per-
                # session VLAN range (1:1, BNGBlaster's own default when
                # outer-vlan-min/max differ) -- confirmed on a real run
                # this is the actual fix for traffic never being
                # generated: an 8-session 1:1 config always printed
                # "Total PPS of all streams: 0.00" at startup and zero
                # session-traffic/stream-traffic-flows ever appeared in
                # session-counters, while BNGBlaster's own official
                # dhcpn1.json example (N:1, single shared VLAN) printed a
                # real nonzero PPS and session-info's nested
                # "session-traffic" block showed real, growing
                # tx-packets counts. Single outer-vlan (not a min/max
                # range) is also what sidesteps the earlier "VLAN ranges
                # exhausted!" failure for session_count > 1 -- N:1 mode
                # doesn't consume one VLAN per session at all.
                "outer-vlan": 1,
                "vlan-mode": "N:1",
            }],
        },
        "sessions": {
            "count": session_count,
            "start-rate": min(400, max(1, session_count)),
        },
        # Present in every confirmed-working BNGBlaster example config
        # (examples/dhcp11.json, dhcpn1.json) -- {session-global} gives
        # each session its own readable circuit/remote-id even though
        # they now share one VLAN (N:1 above), which session-info
        # confirmed populating correctly on a real run.
        "access-line": {
            "agent-remote-id": "RTBRICK.{session-global}",
            "agent-circuit-id": "0.0.0.0/0.0.0.0 eth 0:{session-global}",
        },
        # broadcast:false -- matches the confirmed-working examples;
        # with N:1 putting every session on the same shared VLAN/
        # broadcast domain, unicasting DHCP replies where possible
        # avoids every other session's client also having to filter out
        # replies not addressed to it.
        "dhcp": {"enable": True, "broadcast": False},
        # Confirmed on a real run: with DHCPv6 left at BNGBlaster's
        # default (enabled), every session got a real, fully-bound IPv4
        # lease (dhcp-state="Bound", dhcp-sessions-established=8/8) but
        # stayed stuck at session-state="IPoE Setup"/session-substate=
        # "DHCPv6 pending" forever (sessions-established=0/8) -- this
        # pipeline never set up a DHCPv6 server (deploy/setup_bng_netns.sh
        # disables IPv6 entirely on veth-a/veth-n), so DHCPv6 could never
        # complete and the session-level (v4+v6 combined) established
        # flag never flipped, even though the only protocol this attack
        # simulation actually needs (IPv4) was already fully working.
        "dhcpv6": {"enable": False},
        # Disabling DHCPv6 above wasn't enough on its own -- confirmed on
        # a real run: with dhcpv6.enable=false, dhcpv6-state correctly
        # showed "Disabled", but session-substate then got stuck at "Wait
        # for ICMPv6 RA" instead -- IPoE's own separate IPv6 Router
        # Solicitation/Advertisement exchange, independent of DHCPv6. No
        # IPv6 router exists on this setup (veth-a/veth-n have IPv6
        # disabled entirely -- see setup_bng_netns.sh's disable_ipv6), so
        # that RA could never arrive either. "ipoe": {"ipv6": false}
        # turns off RS/RA for IPoE specifically (separate config block
        # from "dhcp"/"dhcpv6", confirmed via BNGBlaster's own docs).
        "ipoe": {"ipv6": False, "ipv4": True},
        # Confirmed via a real run's diagnostic (BNGBlaster's own
        # dhcpn1.json example, N:1 mode): session-traffic with
        # ipv4-pps=1 produced a real, growing tx-packets count and a
        # nonzero "Total PPS of all streams" at startup -- the access
        # interface's vlan-mode (now N:1 above) was the actual blocker,
        # not session-traffic vs streams. Left disabled (0, the schema
        # default) now that the real fix is applied to "streams" too --
        # this pipeline's attack shaping (protocol/port/pps per
        # scenario) needs "streams", session-traffic's flat ipv4-pps
        # can't express that.
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
        # The stream's own "name" -- what stream-start/stream-stop
        # actually filter by (confirmed on a real run: a "stream-group-id"
        # argument gets a clean {"status":"error","message":"invalid
        # argument"}; the control socket's real stream-start/-stop
        # arguments are name/session-id/flow-id/etc, no group-id at all).
        # Only meaningful for attack_kind="stream" -- icmp-client-start/
        # -stop still use the (unverified) icmp-client-group-id.
        "attack_name": f"attack-{scenario}" if p["kind"] == "stream" else None,
        "protocol": p["protocol"],
        "dst_port": p["dst_port"],
        "autostart": autostart,
    }
