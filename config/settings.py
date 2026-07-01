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
# Must stay well BELOW COLLECT_INTERVAL (above), not just below it --
# flow-stats requests go out once per COLLECT_INTERVAL (_monitor's loop),
# so normal hub.sleep/processing jitter routinely makes the real dt
# between two polls land slightly under COLLECT_INTERVAL. When this was
# 0.5 and COLLECT_INTERVAL got lowered to 0.5 too (for mobile-domain
# sub-second latency), that jitter alone made FlowCollector skip a large
# fraction of openflow's flow-stats samples every cycle.
MIN_FLOW_RATE_DT = 0.1

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

# Domains whose mitigation is inherently per-source (one quarantine action
# per attacking UE/session, not one destination-wide network lever the way
# an OpenFlow drop rule is) -- OrchestrationController's per-UE/per-session
# block/unblock branches (_build_actions, dispatch(), check_mobile_unblocks)
# both key off this tuple instead of a hardcoded "mobile" string, so
# BroadbandAdapter's per-session BNGBlaster sessions reuse the exact same
# machinery MobileNetworkAdapter's per-UE quarantine already validated.
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
