"""
bng_config.py — builds the BNGBlaster JSON test config for the Fixed
Broadband Domain attack simulator (simulation/bng_traffic_simulator.py).

BNGBlaster has no "attack mode" -- every scenario here is a deliberate
combination of its own real features:

  TCP SYN Flood / UDP Flood / Distributed TCP SYN Flood / Low and Slow:
      one or more PPPoE/IPoE sessions, each running BNGBlaster's own
      built-in "session-traffic" generator (a real, confirmed-working
      bidirectional IPv4 pps stream between session and network
      interface) at the scenario's configured rate.
  ICMP Flood:
      one session, BNGBlaster's own `icmp-client` block
      (https://rtbrick.github.io/bngblaster/icmp.html) -- a real ICMP
      echo-request generator.

IMPORTANT, confirmed across several real runs on the installed
BNGBlaster 0.9.17 binary: the documented `streams` config block
(custom per-stream destination IP/port/protocol, raw-tcp framing, etc.)
NEVER created any actual traffic flow on this version, regardless of
vlan-mode, interfaces.network shape, or stream-start argument fixes --
"Total PPS of all streams" stayed 0.00 and session-streams' nested
"streams" array stayed empty every time, while the EXACT same config
with session-traffic added alongside it showed session-traffic's flows
immediately (tx-pps matching the configured ipv4-pps exactly). So this
generator uses session-traffic exclusively, NOT the streams mechanism
its docs would suggest -- session-traffic only offers a flat,
undifferentiated ipv4-pps between session and network interface (no
custom destination IP/port/protocol shaping at the packet level), so
the protocol/dst_port/dst_ip a scenario claims to be simulating (e.g.
"TCP_SYN to port 443") is supplied by bng_traffic_simulator.py itself
when it writes the telemetry CSV row, not detected from real packet
contents -- the same "synthetic producer already knows what it's
simulating" convention simulation/ul_traffic_simulator.py already uses
for the mobile domain (real KPM telemetry has no L4 visibility either).

session-traffic has no per-protocol knob (just one ipv4-pps rate for
all of a session's IPv4 traffic) -- there's no separate "baseline" vs
"attack" stream the way the (nonfunctional) streams approach had,
which previously made an attack visually stand out against a nonzero
floor. Accepted here: an attacking session's reported pps simply goes
from 0 (session-traffic stopped) to the configured attack rate, and
back to 0 once stopped -- the same convention DetectionResult/
TelemetryEvent already use elsewhere for "no signal" (pps=0 rows are
dropped before ever reaching the CSV, same as before).

vlan-mode is N:1 (every session shares ONE VLAN, distinguished by
per-session MAC only), NOT BNGBlaster's 1:1 default (one VLAN per
session) -- confirmed via a real-run diagnostic against BNGBlaster's
own examples/dhcpn1.json that N:1 is what let session-traffic actually
produce nonzero PPS at all; 1:1 always printed "Total PPS of all
streams: 0.00" regardless of which traffic mechanism was configured.
N:1 also sidesteps the earlier "VLAN ranges exhausted!" failure for
session_count > 1 a different way (not consuming one VLAN per session).
"""

from typing import Optional

ATTACK_ICMP_GROUP_ID = 200

SCENARIOS = ("syn_flood", "udp_flood", "icmp_flood", "distributed_syn_flood", "low_and_slow")

# Per-scenario (session_count, per-session pps, kind). pps values are
# picked the same way ul_traffic_simulator.py's scenario_* functions
# pick attack_mbps: comfortably past config/settings.py's threshold for
# the matching attack_type, not tuned against anything BNGBlaster-side
# (BNGBlaster doesn't classify traffic -- detection happens downstream in
# DDoSDetectionEngine once these counters reach a TelemetryEvent).
#
# config/settings.py thresholds each is tuned against:
#   SYN_THRESHOLD=10 pps, UDP_THRESHOLD=200 pps, ICMP_THRESHOLD=150 pps
#   DIST_MIN_SOURCES=5, DIST_ENTROPY_THRESHOLD=0.7 (near-equal per-source rate)
#   LOW_SLOW_MOBILE_MAX_PPS=8.0 (ceiling), LOW_SLOW_MOBILE_MIN_SOURCES=5
#
# pps is rounded to an integer by BNGBlaster's own tx-pps counter
# (confirmed on a real run: ipv4-pps=1 read back as exactly "tx-pps":
# 1, never a fractional value) -- low_and_slow's rate is bumped to 1
# pps (not e.g. 0.05) so it reads as a real nonzero signal at all,
# still comfortably under LOW_SLOW_MOBILE_MAX_PPS=8.0.
_SCENARIO_PARAMS = {
    # single attacker, well past SYN_THRESHOLD=10
    "syn_flood":             dict(sessions=1, pps=200.0, kind="session-traffic", protocol="TCP_SYN", dst_port=443),
    # single attacker, well past UDP_THRESHOLD=200
    "udp_flood":             dict(sessions=1, pps=5000.0, kind="session-traffic", protocol="UDP", dst_port=0),
    # single attacker, icmp-client interval sized for ~300 req/s (well past ICMP_THRESHOLD=150)
    "icmp_flood":            dict(sessions=1, interval=0.0033, kind="icmp", protocol="ICMP", dst_port=0),
    # 8 sessions (>= DIST_MIN_SOURCES=5), 5 pps each -> ~40 pps aggregate
    # (> SYN_THRESHOLD=10), uniform per-session rate -> high entropy
    "distributed_syn_flood": dict(sessions=8, pps=5.0, kind="session-traffic", protocol="TCP_SYN", dst_port=443),
    # 8 sessions (>= LOW_SLOW_MOBILE_MIN_SOURCES=5), each well under
    # LOW_SLOW_MOBILE_MAX_PPS=8.0 -- deliberately not a flood
    "low_and_slow":          dict(sessions=8, pps=1.0, kind="session-traffic", protocol="TCP_SYN", dst_port=443),
}


def _base_config(
    access_interface: str,
    network_interface: str,
    session_count: int,
    network_ip: str,
    network_gateway: str,
    session_traffic_pps: float,
    session_traffic_autostart: bool,
    icmp_client_group_id: int = 0,
) -> dict:
    access_entry = {
        "interface": access_interface,
        "type": "ipoe",
        # N:1 -- see module docstring for why (confirmed real-run
        # fix for traffic never being generated at all).
        "outer-vlan": 1,
        "vlan-mode": "N:1",
    }
    if icmp_client_group_id:
        # Confirmed against the real bbl_config.c source: a session only
        # gets attached to an "icmp-client" config block if its access
        # interface declares this SAME group id (access_config->
        # icmp_client_group_id) -- exactly the same group-id-pairing
        # pattern the (abandoned) "streams" mechanism needed. Without it,
        # `icmp-clients session-id 1` returned a real but empty `[]` on
        # a real run -- the icmp-client config was accepted at load time
        # but never bound to any session, so icmp-clients-start had
        # nothing to start (no error, no traffic, silently a no-op).
        access_entry["icmp-client-group-id"] = icmp_client_group_id
    return {
        "interfaces": {
            # A plain object, NOT wrapped in a list -- the upstream JSON
            # schema (current main branch) allows either via oneOf, but
            # BNGBlaster 0.9.17 (the last release with an ubuntu-20.04
            # build, what's actually installed here -- see deploy/
            # install_bngblaster.sh) predates that schema; every
            # confirmed-working example from ITS OWN tag (examples/
            # dhcp11.json, dhcpn1.json) uses a bare object here.
            "network": {
                "interface": network_interface,
                "address": network_ip,
                "gateway": network_gateway,
            },
            "access": [access_entry],
        },
        "sessions": {
            "count": session_count,
            "start-rate": min(400, max(1, session_count)),
        },
        # Present in every confirmed-working BNGBlaster example config
        # (examples/dhcp11.json, dhcpn1.json) -- {session-global} gives
        # each session its own readable circuit/remote-id even though
        # they now share one VLAN (N:1 above).
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
        # lease but stayed stuck at session-state="IPoE Setup"/
        # session-substate="DHCPv6 pending" forever (sessions-
        # established=0) -- this pipeline never set up a DHCPv6 server
        # (deploy/setup_bng_netns.sh disables IPv6 entirely on
        # veth-a/veth-n), so DHCPv6 could never complete.
        "dhcpv6": {"enable": False},
        # Disabling DHCPv6 above wasn't enough on its own -- confirmed on
        # a real run: with dhcpv6.enable=false, a session then got stuck
        # at session-substate="Wait for ICMPv6 RA" instead -- IPoE's own
        # separate IPv6 Router Solicitation/Advertisement exchange,
        # independent of DHCPv6. No IPv6 router exists on this setup, so
        # that RA could never arrive either. "ipoe": {"ipv6": false}
        # turns off RS/RA for IPoE specifically.
        "ipoe": {"ipv6": False, "ipv4": True},
        # The actual traffic generator this pipeline relies on -- see
        # module docstring for why, not the documented "streams" block.
        # autostart=false for every scenario except low_and_slow (the
        # orchestrator starts/stops it explicitly via the control
        # socket's session-traffic-start/-stop at the configured attack
        # tick -- mirrors attack_window in ul_traffic_simulator.py).
        "session-traffic": {
            "autostart": session_traffic_autostart,
            "ipv4-pps": session_traffic_pps,
        },
    }


def build_scenario(
    scenario: str,
    target_ip: str,
    access_interface: str = "veth-a",
    network_interface: str = "veth-n",
    network_ip: str = "10.50.0.10/24",
    network_gateway: str = "10.50.0.1",
    attack_autostart: Optional[bool] = None,
) -> dict:
    """
    Returns {"config": <bngblaster JSON config>, "sessions": int,
    "attack_kind": "session-traffic"|"icmp", "protocol": str,
    "dst_port": int, "autostart": bool}.

    attack_autostart: if None, defaults to True for "low_and_slow"
    (continuous-from-start by definition) and False for every other
    scenario (the orchestrator starts it explicitly at the configured
    attack tick, via the control socket).
    """
    if scenario not in _SCENARIO_PARAMS:
        raise ValueError(f"unknown scenario {scenario!r}, expected one of {SCENARIOS}")
    p = _SCENARIO_PARAMS[scenario]
    session_count = p["sessions"]
    autostart = attack_autostart if attack_autostart is not None else (scenario == "low_and_slow")

    if p["kind"] == "session-traffic":
        cfg = _base_config(
            access_interface, network_interface, session_count, network_ip, network_gateway,
            session_traffic_pps=p["pps"], session_traffic_autostart=autostart,
        )
    elif p["kind"] == "icmp":
        # Confirmed against the real bbl_access.c source
        # (bbl_access_rx_established_ipoe): a session's IPv4 "endpoint"
        # only flips from ENABLED to ACTIVE once it has both a real IP
        # AND session->arp_resolved is true -- and icmp-client's own send
        # job silently no-ops forever if that endpoint isn't ACTIVE
        # (bbl_icmp_client_send_job_ping: "if (session->endpoint.ipv4 !=
        # ENDPOINT_ACTIVE) return;"). Confirmed on a real run: with
        # session-traffic fully disabled, tx-icmp stayed at 0 the entire
        # time even with icmp-clients-start successfully called -- nothing
        # ever triggered the session to ARP at all. A small always-on
        # session-traffic (autostart=true) gives the session a reason to
        # ARP and activate its endpoint; the actual measured/attack
        # traffic is still the icmp-client below, not this.
        cfg = _base_config(
            access_interface, network_interface, session_count, network_ip, network_gateway,
            session_traffic_pps=1, session_traffic_autostart=True,
            icmp_client_group_id=ATTACK_ICMP_GROUP_ID,
        )
        # icmp-client has no documented "autostart" field -- it starts
        # sending as soon as the session is up. The orchestrator
        # controls its timing via icmp-client-start/-stop on the
        # control socket instead (assumed command names -- this
        # mechanism, unlike session-traffic, has NOT been confirmed
        # against a real run yet).
        #
        # "icmp-client-group-id" (session-scoped, one client per
        # access session) and "network-interface" (a standalone client
        # bound to a network interface instead, no session involved)
        # are mutually exclusive -- confirmed on a real run: specifying
        # both got a hard config-load error ("At most one
        # icmp-client-group-id or network-interface must be specified
        # for icmp-clients."). This scenario wants the per-session
        # variant (matching syn_flood/udp_flood's model: the attacking
        # SESSION sends the flood), so network-interface is omitted.
        cfg["icmp-client"] = [{
            "icmp-client-group-id": ATTACK_ICMP_GROUP_ID,
            "destination-address": target_ip,
            "interval": p["interval"],
            "count": 0,
        }]
    else:
        raise AssertionError(f"unreachable: kind={p['kind']!r}")

    return {
        "config": cfg,
        "sessions": session_count,
        "attack_kind": p["kind"],
        "attack_group_id": ATTACK_ICMP_GROUP_ID if p["kind"] == "icmp" else None,
        "protocol": p["protocol"],
        "dst_port": p["dst_port"],
        "autostart": autostart,
    }
