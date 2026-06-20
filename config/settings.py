FLOW_WINDOW = 20
COLLECT_INTERVAL = 5

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
