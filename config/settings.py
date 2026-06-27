FLOW_WINDOW = 20

# Pipeline cadence (controller/ryu_controller_2.py's _monitor loop): how
# often the full collect -> correlate -> detect -> decide -> mitigate
# pipeline runs. Lowered from 5s to get sub-second detection latency for
# the mobile-domain UE-throttle tests -- run ul_traffic_simulator.py with
# --tick at or below this value too, otherwise the controller can poll
# faster than fresh attack-magnitude samples actually land in the CSV.
# NOTE: still >= MIN_FLOW_RATE_DT (below) so openflow's own flow-stats
# rate sampling keeps trusting its samples if/when that domain is
# exercised with real switches again.
COLLECT_INTERVAL = 0.5

SYN_THRESHOLD = 10
UDP_THRESHOLD = 200
ICMP_THRESHOLD = 150

LOW_SLOW_NEW_FLOWS = 20
LOW_SLOW_MIN_BYTES = 500

# Minimum age (seconds) a flow must have before a low byte count counts as
# "stalled" rather than "just started, hasn't sent much yet". Must stay
# comfortably below VALIDATED_FLOW_HARD_TIMEOUT (30s) — that hard_timeout
# resets the underlying OpenFlow rule (and its duration_sec/byte_count
# counters) periodically, so a threshold at or above it would never be
# reachable within a single rule's lifetime.
LOW_SLOW_MIN_AGE = 15

# How long (seconds) a (src_ip, dst_ip) pair's distinct-source-port tally
# (DDoSCollector.get_connection_port_counts, for single-source low-and-slow
# detection) is kept after that pair last appeared in packet-in, before
# being forgotten. Generous on purpose — a real attack keeps the same
# connections open for a long time, and this entry only updates when
# packet-in happens to see that pair at all (sparse for a slow attack).
LOW_SLOW_PORT_IDLE_TTL = 90

DECISION_THRESHOLD = 1.5

BLOCK_TIME = 60

# Flow priority used for mitigation drop rules (OpenFlowMitigator). Shared
# with FlowCollector so it can exclude these from polled flow stats — a
# drop rule still counts matched (dropped) packets, and if that volume got
# fed back into telemetry, the mitigation's own counters would look like a
# fresh attack and trigger a second, redundant block.
MITIGATION_DROP_PRIORITY = 100

# Minimum elapsed time (seconds) between two samples of the same flow
# before FlowCollector trusts the resulting rate. Two OFPFlowStatsReply
# messages can land back-to-back (e.g. two switches replying close
# together, or the controller catching up after being busy) with a near-
# zero dt — dividing a normal packet_delta by that tiny dt produces a
# physically impossible rate (seen once: ~470M pps). Below this floor the
# sample is skipped rather than trusted.
MIN_FLOW_RATE_DT = 0.5

# Forced lifetime of a *validated* L3 forwarding rule (LearningSwitch),
# regardless of how continuously it's being used. Without a hard_timeout,
# a rule under continuous traffic never expires (idle_timeout keeps
# resetting), so it never triggers a fresh packet-in either — meaning
# OpenFlowAdapter's per-(src,dst) protocol/port metadata (_flow_meta),
# learned only from packet-in, can go stale for as long as the rule lives.
# E.g. a ping between two hosts caches an "ICMP" tag; if those same two
# hosts start a UDP flood minutes later, it silently reuses the cached
# rule and never refreshes that tag. This timeout forces periodic
# re-classification — matches telemetry/openflow_adapter.py's
# _FLOW_META_TTL so a rule never outlives the metadata it depends on.
VALIDATED_FLOW_HARD_TIMEOUT = 30

# Distributed / spoofed-source attack detection (IP flow entropy).
# A destination under attack from many distinct, individually-low-volume
# sources looks like an even (high-entropy) distribution of traffic across
# source IPs — the classic signature of a spoofed-source volumetric flood.
DIST_MIN_SOURCES = 5          # need at least this many distinct sources
DIST_ENTROPY_THRESHOLD = 0.7  # normalized Shannon entropy (0-1) of src distribution
DIST_PPS_THRESHOLD = 300      # aggregate pps across all sources toward one dst

# Low-and-slow detection for the mobile domain (DDoSDetectionEngine.
# analyze_low_slow_mobile). The RAN's per-UE KPM telemetry has no
# connection/flow-count visibility the way OpenFlow's flow table does
# (LOW_SLOW_NEW_FLOWS above), so a single UE sending a low, flat rate
# forever can't be told apart from ordinary background traffic by rate or
# duration alone -- every benign UE looks like that. The analogous
# mobile-domain signature is instead "how many distinct UEs are
# simultaneously holding a low, sub-threshold rate toward the same
# destination, and for how long" -- many slow contributors at once is the
# anomaly, not any single one of them.
LOW_SLOW_MOBILE_MAX_PPS = 8.0      # below SYN_THRESHOLD -- "low rate" band ceiling
LOW_SLOW_MOBILE_MIN_SOURCES = 5    # distinct low-rate UEs toward one dst, same cycle
LOW_SLOW_MOBILE_MIN_CYCLES = 20    # consecutive cycles that count must hold before flagging

# Domains whose mitigation is inherently per-source (one quarantine action
# per attacking UE/session, not one destination-wide network lever the way
# an OpenFlow drop rule is) -- DDoSDetectionEngine.analyze_low_slow_mobile
# (despite its name, now domain-generic -- see its docstring) and
# OrchestrationController's per-UE/per-session block/unblock branches
# (_build_actions, dispatch(), check_mobile_unblocks) both key off this
# tuple instead of a hardcoded "mobile" string, so BroadbandAdapter's
# per-session BNGBlaster sessions reuse the exact same machinery
# MobileNetworkAdapter's per-UE quarantine already validated.
PER_SOURCE_MITIGATION_DOMAINS = ("mobile", "broadband")

# Domains whose block is a complete cutoff, not a throttle -- mobile's
# RC quarantine drops a UE's rate near zero but it keeps reporting
# telemetry every cycle (ul_traffic_simulator.py's UEs always sample),
# while BroadbandAdapter's session-stop kills the BNGBlaster session
# entirely, so collect() produces ZERO TelemetryEvents for it until
# session-start. Confirmed on a real run: feeding that into
# check_mobile_unblocks's presence-based signal misread "no telemetry
# because we just blocked it" as "the attacker stopped", unblocking
# within UNBLOCK_CONFIRM_CYCLES regardless of whether the attack was
# still running -- a fast, repeating BLOCK/UNBLOCK/re-detect oscillation
# instead of one stable block for the duration of the attack. Domains
# here use a fixed wall-clock hold (MitigationAction.duration) instead.
PRESENCE_BLIND_DOMAINS = ("broadband",)
