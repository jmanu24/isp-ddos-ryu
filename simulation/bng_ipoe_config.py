"""
bng_ipoe_config.py — per-scenario parameters for the Broadband domain's
distributed-mode attack simulator (simulation/bng_subscriber_agent.py),
driven by real per-subscriber IPs (accel-ppp on `bng`), REPLACING
simulation/bng_config.py's BNGBlaster session-traffic parameters -- see
bngblaster_broadband_pipeline_status memory for why BNGBlaster itself
was dropped (an unresolved packet-transmission bug on this lab).

Same "comfortably past config/settings.py's threshold for the matching
attack_type" sizing convention bng_config.py's own _SCENARIO_PARAMS
used, just against the real detection thresholds:
  SYN_THRESHOLD=10 pps, UDP_THRESHOLD=200 pps, ICMP_THRESHOLD=150 pps
  DIST_MIN_SOURCES=5, DIST_ENTROPY_THRESHOLD=0.7 (near-equal per-source rate)
  LOW_SLOW_MOBILE_MAX_PPS=8.0 (ceiling), LOW_SLOW_MOBILE_MIN_SOURCES=5

subscriber_count picks how many of the macvlan-backed subscriber
sessions (roles/suscriptor's setup_macvlans.sh.j2, macvlan1..N)
participate -- 1 for the single-attacker scenarios, 8 (>=
DIST_MIN_SOURCES) for the distributed/low-and-slow ones, uniform rate
per subscriber so DDoSDetectionEngine's entropy check reads high.

pps is a generic target rate, None meaning "as fast as possible"
(a flood) -- bng_subscriber_agent.py translates this into whatever the
actual generator for that protocol needs (ping's own -i/-f flags for
ICMP, or a --pps argument to simulation/bng_flood.py for TCP_SYN/UDP).
Kept protocol-agnostic here on purpose: this file used to store
hping3's own rate-flag syntax directly, but hping3 turned out to be
unusable in this lab regardless of access mode (see
bng_subscriber_agent.py's own module docstring) and was replaced
per-protocol, so a single generic number is the right level of detail
for this config.
"""

SCENARIOS = (
    "syn_flood", "udp_flood", "icmp_flood",
    "distributed_syn_flood", "distributed_udp_flood", "distributed_icmp_flood",
    "low_and_slow",
)

BASELINE_SCENARIO = "low_and_slow"


SCENARIO_PARAMS = {
    "syn_flood": dict(
        subscriber_count=1, protocol="TCP_SYN", dst_port=443,
        pps=None, autostart=False,
    ),
    "udp_flood": dict(
        subscriber_count=1, protocol="UDP", dst_port=0,
        pps=None, autostart=False,
    ),
    "icmp_flood": dict(
        subscriber_count=1, protocol="ICMP", dst_port=0,
        pps=None, autostart=False,
    ),
    # 8 subscribers (>= DIST_MIN_SOURCES=5), 5 pps each -> ~40 pps
    # aggregate (> SYN_THRESHOLD=10), uniform per-subscriber rate ->
    # high entropy.
    "distributed_syn_flood": dict(
        subscriber_count=8, protocol="TCP_SYN", dst_port=443,
        pps=5.0, autostart=False,
    ),
    # 8 x 60 pps = 480 aggregate (> UDP_THRESHOLD=200).
    "distributed_udp_flood": dict(
        subscriber_count=8, protocol="UDP", dst_port=0,
        pps=60.0, autostart=False,
    ),
    # 8 x 50 pps = 400 aggregate (> ICMP_THRESHOLD=150).
    "distributed_icmp_flood": dict(
        subscriber_count=8, protocol="ICMP", dst_port=0,
        pps=50.0, autostart=False,
    ),
    # 8 subscribers (>= LOW_SLOW_MOBILE_MIN_SOURCES=5), 1 pps each --
    # well under LOW_SLOW_MOBILE_MAX_PPS=8.0, deliberately not a flood.
    # Autostarts the moment the agent comes up, same as BNGBlaster's own
    # low_and_slow scenario did (this domain's standing baseline).
    "low_and_slow": dict(
        subscriber_count=8, protocol="TCP_SYN", dst_port=443,
        pps=1.0, autostart=True,
    ),
}

_NORMAL_DST_PORT = 80
_NORMAL_PROTOCOL = "TCP"


def build_scenario(scenario: str) -> dict:
    if scenario not in SCENARIO_PARAMS:
        raise ValueError(f"unknown scenario {scenario!r}, expected one of {SCENARIOS}")
    return dict(SCENARIO_PARAMS[scenario])
