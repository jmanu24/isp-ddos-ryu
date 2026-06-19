FLOW_WINDOW = 20
COLLECT_INTERVAL = 5

SYN_THRESHOLD = 10
UDP_THRESHOLD = 200
ICMP_THRESHOLD = 150

LOW_SLOW_NEW_FLOWS = 20
LOW_SLOW_MIN_BYTES = 500

DECISION_THRESHOLD = 1.5

BLOCK_TIME = 60

# Flow priority used for mitigation drop rules (OpenFlowMitigator). Shared
# with FlowCollector so it can exclude these from polled flow stats — a
# drop rule still counts matched (dropped) packets, and if that volume got
# fed back into telemetry, the mitigation's own counters would look like a
# fresh attack and trigger a second, redundant block.
MITIGATION_DROP_PRIORITY = 100

# Distributed / spoofed-source attack detection (IP flow entropy).
# A destination under attack from many distinct, individually-low-volume
# sources looks like an even (high-entropy) distribution of traffic across
# source IPs — the classic signature of a spoofed-source volumetric flood.
DIST_MIN_SOURCES = 5          # need at least this many distinct sources
DIST_ENTROPY_THRESHOLD = 0.7  # normalized Shannon entropy (0-1) of src distribution
DIST_PPS_THRESHOLD = 300      # aggregate pps across all sources toward one dst
