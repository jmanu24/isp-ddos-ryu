"""
bng_ipoe_config.py — per-scenario parameters for the Broadband domain's
distributed-mode attack simulator (simulation/bng_subscriber_agent.py),
now driven by real hping3 processes sourced from real per-subscriber
DHCP-assigned IPs (accel-ppp on `bng`), REPLACING simulation/bng_config.
py's BNGBlaster session-traffic parameters -- see
bngblaster_broadband_pipeline_status memory for why BNGBlaster itself
was dropped (an unresolved packet-transmission bug on this lab).

Same "comfortably past config/settings.py's threshold for the matching
attack_type" sizing convention bng_config.py's own _SCENARIO_PARAMS
used -- not tuned against BNGBlaster's specific counter-rounding
behavior anymore (hping3 has no such quirk), just against the real
detection thresholds:
  SYN_THRESHOLD=10 pps, UDP_THRESHOLD=200 pps, ICMP_THRESHOLD=150 pps
  DIST_MIN_SOURCES=5, DIST_ENTROPY_THRESHOLD=0.7 (near-equal per-source rate)
  LOW_SLOW_MOBILE_MAX_PPS=8.0 (ceiling), LOW_SLOW_MOBILE_MIN_SOURCES=5

subscriber_count picks how many of the macvlan-backed subscriber
sessions (roles/suscriptor's setup_macvlans.sh.j2, macvlan1..N)
participate -- 1 for the single-attacker scenarios, 8 (>=
DIST_MIN_SOURCES) for the distributed/low-and-slow ones, uniform rate
per subscriber so DDoSDetectionEngine's entropy check reads high.

rate_flags is hping3's own per-process rate control: "--flood" for an
uncontrolled, fastest-possible single attacker (comfortably past any
threshold with no need for a precise number), "-i", "u<microseconds>"
for a controlled, precise per-subscriber pps (interval_usec =
1_000_000 // target_pps) -- needed for the distributed/low-and-slow
scenarios, where a per-subscriber rate that's too high would just look
like one loud attacker rather than many uniform ones.
"""

SCENARIOS = (
    "syn_flood", "udp_flood", "icmp_flood",
    "distributed_syn_flood", "distributed_udp_flood", "distributed_icmp_flood",
    "low_and_slow",
)

BASELINE_SCENARIO = "low_and_slow"


def _interval_flags(pps: float) -> list:
    usec = max(1, int(1_000_000 // pps))
    return ["-i", f"u{usec}"]


SCENARIO_PARAMS = {
    "syn_flood": dict(
        subscriber_count=1, protocol="TCP_SYN", dst_port=443,
        rate_flags=["--flood"], autostart=False,
    ),
    "udp_flood": dict(
        subscriber_count=1, protocol="UDP", dst_port=0,
        rate_flags=["--flood"], autostart=False,
    ),
    "icmp_flood": dict(
        subscriber_count=1, protocol="ICMP", dst_port=0,
        rate_flags=["--flood"], autostart=False,
    ),
    # 8 subscribers (>= DIST_MIN_SOURCES=5), 5 pps each -> ~40 pps
    # aggregate (> SYN_THRESHOLD=10), uniform per-subscriber rate ->
    # high entropy.
    "distributed_syn_flood": dict(
        subscriber_count=8, protocol="TCP_SYN", dst_port=443,
        rate_flags=_interval_flags(5.0), autostart=False,
    ),
    # 8 x 60 pps = 480 aggregate (> UDP_THRESHOLD=200).
    "distributed_udp_flood": dict(
        subscriber_count=8, protocol="UDP", dst_port=0,
        rate_flags=_interval_flags(60.0), autostart=False,
    ),
    # 8 x 50 pps = 400 aggregate (> ICMP_THRESHOLD=150).
    "distributed_icmp_flood": dict(
        subscriber_count=8, protocol="ICMP", dst_port=0,
        rate_flags=_interval_flags(50.0), autostart=False,
    ),
    # 8 subscribers (>= LOW_SLOW_MOBILE_MIN_SOURCES=5), 1 pps each --
    # well under LOW_SLOW_MOBILE_MAX_PPS=8.0, deliberately not a flood.
    # Autostarts the moment the agent comes up, same as BNGBlaster's own
    # low_and_slow scenario did (this domain's standing baseline).
    "low_and_slow": dict(
        subscriber_count=8, protocol="TCP_SYN", dst_port=443,
        rate_flags=_interval_flags(1.0), autostart=True,
    ),
}

_NORMAL_DST_PORT = 80
_NORMAL_PROTOCOL = "TCP"


def build_scenario(scenario: str) -> dict:
    if scenario not in SCENARIO_PARAMS:
        raise ValueError(f"unknown scenario {scenario!r}, expected one of {SCENARIOS}")
    return dict(SCENARIO_PARAMS[scenario])
