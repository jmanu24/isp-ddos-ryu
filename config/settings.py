import os

# Number of OVS switches (and therefore real enterprise/mobile/broadband
# hosts, one of each per switch) topologies/star_topology.py's
# build_topology() creates. Was a hardcoded default of 4 -- raised so
# enterprise's own DDoS cell (docs/thesis-revision-plan.md's 24-scenario
# matrix, 4 domains x 3 vectors x DoS/DDoS) can actually cross
# DIST_MIN_SOURCES (below): enterprise attacks are real, unspoofed
# per-host traffic (webtool/enterprise_ops.py), one distinct source IP
# per switch, so 4 switches structurally capped enterprise at 4 distinct
# sources -- one short of the distributed-detection threshold, a gap
# docs/thesis-revision-plan.md's own review already flagged ("cuatro
# fuentes frente a un umbral de cinco... no valida esa capacidad").
# mobile/broadband don't need this (mobile spoofs extra sources per gNB
# via count_per_gnb, broadband uses dedicated multi-session BNGBlaster
# scenarios), but they get a free 5th real host too since they're built
# from the same per-switch host set.
TOPOLOGY_NUM_SWITCHES = 5

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

# Master switch for every low-and-slow detection variant (OpenFlow flow-
# count, OpenFlow single-source connection-port-count, and the mobile/
# broadband per-source-rate one -- see controller/ryu_controller_2.py's
# _run_pipeline, which gates all three analyze_low_slow* calls on this).
# False means DDoSDetectionEngine never produces a LOW_SLOW DetectionResult
# at all, so decision/orchestration never sees one either -- there's
# nothing downstream to separately disable, mitigation for this type is
# entirely a function of a detection existing in the first place.
LOW_SLOW_DETECTION_ENABLED = False

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
# Must stay well BELOW COLLECT_INTERVAL (above), not just below it --
# flow-stats requests go out once per COLLECT_INTERVAL (_monitor's loop),
# so normal hub.sleep/processing jitter routinely makes the real dt
# between two polls land slightly under COLLECT_INTERVAL. When this was
# 0.5 and COLLECT_INTERVAL got lowered to 0.5 too (for mobile-domain
# sub-second latency), that jitter alone made FlowCollector skip a large
# fraction of openflow's flow-stats samples every cycle -- starving
# SYN_FLOOD's volumetric (flow-stats-based) detection while LOW_SLOW's
# distinct-source-port count (packet-in-based, not subject to this floor
# at all) kept climbing unimpeded and won the race almost every time.
# Confirmed on a real run: hping3 --flood, previously classified
# correctly as SYN_FLOOD, got misclassified as LOW_SLOW with a BLOCK/
# UNBLOCK oscillation once COLLECT_INTERVAL and this floor collided.
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
# MobileNetworkAdapter's per-UE quarantine already validated. "bgp" joined
# this set for the same reason: BGP FlowSpec is a per-source discard route
# (one exact 5-tuple match, not a destination-wide network lever either),
# so it reuses this same per-source block/unblock machinery -- see
# docs/peering-plan.md §6 for why a hand-rolled bgp-specific tracking
# dict/check function turned out to be unnecessary.
PER_SOURCE_MITIGATION_DOMAINS = ("mobile", "broadband", "bgp")

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
# "bgp" belongs here for the OPPOSITE reason broadband does -- its block
# doesn't cut telemetry off, softflowd captures on r1-ext0 BEFORE the
# FlowSpec rule ever gets a chance to drop the packet, so the attacker
# would keep showing up as "present" in telemetry forever, even with the
# block fully in effect. Either way (telemetry vanishes vs. telemetry
# never reflects the block at all), a presence-based signal can't tell
# whether the block is working, so both domains fall back to the same
# fixed wall-clock TTL instead.
PRESENCE_BLIND_DOMAINS = ("broadband", "bgp")

# --- BGP Peering domain (see docs/peering-plan.md) --------------------
# Overrides MitigationAction's own 60s dataclass default (core/models.py)
# for bgp specifically -- see orchestration/controller.py's `elif
# src_domain == "bgp":` branch. Left at the 60s default for broadband/
# mobile (the other two PRESENCE_BLIND_DOMAINS/PER_SOURCE_MITIGATION_
# DOMAINS members): broadband's own real-lab Tr was already ~40s and
# didn't need tuning, and mobile's RC-throttle duration (telemetry/
# mobile_adapter.py's apply_mitigation) is a different, untested
# real-lab mechanism this change has no reason to touch. Halved from
# 60 to 30 -- confirmed on a real run this domain's recovery (Tr) was
# dominated by this fixed hold, not by pipeline cycle speed (unlike
# enterprise's UNBLOCK_CONFIRM_CYCLES-based recovery, which SSH
# connection reuse already cut ~4x -- see telemetry/broadband_adapter.
# py's and collectors/peering_flow_collector.py's _ssh()/_ssh_br()).
# Tradeoff: a spoofed/bursty attacker that pauses for >30s and resumes
# gets a fresh FlowSpec announce instead of staying continuously
# blocked, same bounce risk UNBLOCK_CONFIRM_CYCLES trades off for
# enterprise, just via wall-clock instead of cycle count.
PEERING_UNBLOCK_HOLD_S = 30

# Directory nfcapd rotates its binary NetFlow/IPFIX capture files into,
# fed by softflowd sniffing r1's external interface. Read via `nfdump`,
# never parsed as raw wire format (collectors/peering_flow_collector.py).
PEERING_NFCAPD_DIR = "/var/cache/nfcapd/r1"
PEERING_NFDUMP_BIN = "nfdump"

# Named pipe exabgp's `api` process section reads announce/withdraw
# commands from (mitigation/peering_backend.py). exabgp itself holds the
# actual BGP session to r1's `flow` instance (github.com/hack3ric/flow)
# -- not FRR, whose own FlowSpec-to-dataplane bridge never installs the
# rule for real (see docs/peering-plan.md §2.1).
PEERING_EXABGP_FIFO = "/run/exabgp/exabgp.in"

# peer_ext's own fixed address -- the single real (unspoofed) external
# source this domain's basic DoS scenario uses. Kept as a named constant
# for scripts/tests that want to address peer_ext specifically, but NOT
# used to filter telemetry (see PEERING_LOCAL_IPS below) -- a DDoS-style
# scenario legitimately sends spoofed traffic FROM peer_ext with many
# different (fake) source IPs, none of which equal this one.
# Must match topologies/star_topology.py's EXTERNAL_PEER_IP -- duplicated
# here rather than imported, since that module pulls in Mininet itself,
# which the controller process has no other reason to depend on.
PEERING_EXTERNAL_PEER_IP = "10.97.0.2"

# softflowd captures BOTH directions of traffic crossing r1-ext0, so
# without filtering, telemetry/bgp_adapter.py would treat these two
# addresses' own outbound traffic as an inbound attack too -- confirmed
# on the VM: a UDP flood from peer_ext produced a SECOND, spurious
# ATTACK_DETECTED ICMP_FLOOD with central_server misattributed as the
# source (the kernel's automatic ICMP "port unreachable" backscatter to
# the flood hitting a closed port), and a BGP_FLOWSPEC_DISCARD issued
# against central_server's own legitimate replies. Real FlowSpec is meant
# to stop traffic reaching a victim FROM an external peer, never to have
# the router discard its own outbound traffic.
# A DENYLIST (exclude known-local addresses), not an ALLOWLIST of the one
# known real peer_ext IP -- a DDoS scenario needs peer_ext's spoofed
# (--rand-source) traffic, with essentially none of it actually equal to
# PEERING_EXTERNAL_PEER_IP above, to still pass through as legitimate
# external attack telemetry. Only central_server (the usual victim, whose
# own replies are the actual backscatter problem) and r1's own external-
# facing address (which could similarly emit e.g. ICMP errors) are ever
# excluded -- everything else, real or spoofed, is treated as a possible
# external attacker.
# Must match topologies/star_topology.py's CENTRAL_SERVER_IP/R1_EXTERNAL_IP.
PEERING_CENTRAL_SERVER_IP = "10.99.0.1"
PEERING_R1_EXTERNAL_IP = "10.97.0.1"

# --- BGP Peering domain: distributed-VM mode (deploy/vm-lab) ----------
# Everything above models r1 + peer_ext + central_server as ONE Linux
# host's own namespaces/veths -- confirmed impossible to run as-is
# across separate VMs: attach_peering_uplink_to_r1() (webtool/
# peering_ops.py) moves a veth into r1's own PID namespace via `ip link
# set ... netns <pid>`, which has no cross-machine equivalent. When this
# flag is on, PeeringLifecycle instead assumes `flow`/softflowd/nfcapd
# are already running as persistent systemd services on a separate `br`
# VM (deploy/vm-lab/ansible/roles/br), and `exabgp` as one on whatever
# host runs this controller (deploy/vm-lab/ansible/roles/orchestrator)
# -- all installed/configured by Ansible, not spawned per-topology-start
# the way the Mininet path spawns flow/exabgp/softflowd/nfcapd today.
#
# Env-var-overridable, the one exception to this file's usual pure-
# constants style -- deliberately, since the SAME checkout of this repo
# runs on two different deployment targets (the existing Mininet-based
# Ubuntu test VM, and deploy/vm-lab's distributed lab), and this flag is
# the one thing that must differ between them without a code edit. The
# distributed lab's orchestrator role sets this in the ryu-manager
# systemd unit's Environment=; nothing sets it on the Mininet VM, so it
# defaults False there unchanged.
PEERING_DISTRIBUTED_MODE = os.environ.get("PEERING_DISTRIBUTED_MODE", "").lower() in ("1", "true", "yes")

# br's real address on VLAN-MGMT (deploy/vm-lab/topology.yaml) -- what
# `flow` binds its exabgp-facing listener to, and what this controller
# SSHes to. Deliberately br's MGMT address, NOT its PEERING one: this
# controller (orchestrator) has no interface on the PEERING VLAN at all
# (only br and peer-router do -- see topology.yaml), so br's PEERING
# address is simply unreachable from here. Replaces PEERING_UPLINK_R1_IP's
# veth address for both purposes (that veth existed specifically so r1
# and the root namespace could reach each other with no real network in
# the way -- MGMT plays the same role here, for real).
PEERING_DIST_BR_IP = "10.10.0.3"

# br's real address on the PEERING VLAN -- NOT what flow binds to (see
# PEERING_DIST_BR_IP above), but the address actually carried on
# PEERING_DIST_BR_EXTERNAL_IFACE, the interface softflowd sniffs. So
# THIS is the one excluded from attack telemetry, the same role
# PEERING_R1_EXTERNAL_IP plays in Mininet mode (br's own traffic on the
# sniffed link, not an external attacker's).
PEERING_DIST_BR_PEERING_IP = "10.30.0.1"

# This controller's own real address on VLAN-MGMT (deploy/vm-lab/
# topology.yaml's `orchestrator`) -- exabgp's local-address/router-id,
# replacing PEERING_UPLINK_ROOT_IP's veth address. Reachable from br
# over the real network with no veth needed.
PEERING_DIST_ORCHESTRATOR_IP = "10.10.0.1"

# br's real PEERING-facing NIC -- what softflowd sniffs, replacing
# EXTERNAL_PEER_IFACE_R1. NOT guaranteed to be `ens192` on a different
# ESXi host/rebuild (see deploy/vm-lab's control-node interface-naming
# notes) -- confirm with `ip link show` on the actual VM before trusting
# this if the lab was ever rebuilt.
PEERING_DIST_BR_EXTERNAL_IFACE = "ens192"

# peer-router's real address -- the distributed-mode equivalent of
# PEERING_EXTERNAL_PEER_IP (Mininet's peer_ext).
PEERING_DIST_EXTERNAL_PEER_IP = "10.30.0.2"

# Non-default TCP port for the flow<->exabgp control channel (flow's own
# `-b`/exabgp's `connect`, see webtool/peering_ops.py's
# _write_exabgp_conf). NOT 179: br also runs FRR's bgpd for the real
# eBGP session with peer-router (deploy/vm-lab/ansible/roles/br), which
# binds the standard BGP port on ALL of br's addresses by default (no
# simple per-address scoping available in FRR for the main listener) --
# flow trying to ALSO bind :179, even on a different specific address,
# fails with "Address already in use". Arbitrary otherwise; just needs
# flow's bind port and exabgp's connect port to agree.
PEERING_DIST_FLOW_PORT = 1790

# SSH target for the `br` VM -- distributed mode has no local process
# handle for flow/softflowd/nfcapd (they're systemd services on a
# different machine), so PeeringLifecycle.start()/stop() only verifies
# they're active via SSH rather than spawning/killing them, and
# collectors/peering_flow_collector.py lists/decodes nfcapd's capture
# files via SSH too (nfcapd writes them to br's own disk, not this
# host's). Must be able to SSH in non-interactively (key-based auth) --
# see deploy/vm-lab/README.md.
PEERING_DIST_BR_SSH_USER = "labadmin"
PEERING_DIST_BR_SSH_HOST = PEERING_DIST_BR_IP

# ---------------------------------------------------------------------
# Broadband domain -- distributed VM lab mode (mirrors PEERING_DISTRIBUTED_
# MODE above). REPLACES the earlier BNGBlaster-based design (see
# bngblaster_broadband_pipeline_status memory: BNGBlaster's own sendto()
# succeeded but the frame was invisible to every external observer on
# this lab, an unresolved bug). See telemetry/broadband_adapter.py's
# DISTRIBUTED MODE docstring and simulation/bng_subscriber_agent.py's
# module docstring for the full picture: `bng` now runs accel-ppp (a
# real open-source BRAS/BNG) fronted by FreeRADIUS -- real per-session
# telemetry comes from FreeRADIUS's own accounting records there, not
# from anything running on `suscriptor`. `suscriptor` runs simulation/
# bng_subscriber_agent.py as a persistent systemd service, driven over
# SSH by the SAME FIFO protocol simulation/bng_agent.py used (baseline/
# attack <scenario>/stop/stop_all) -- webtool/bng_ops.py's BngLifecycle
# didn't need to change at all for this swap.
# ---------------------------------------------------------------------
BNG_DISTRIBUTED_MODE = os.environ.get("BNG_DISTRIBUTED_MODE", "").lower() in ("1", "true", "yes")

# suscriptor's real MGMT address (deploy/vm-lab/topology.yaml) -- no
# longer a hot-added NIC (BNGBlaster's old 3-NIC design is gone, see
# topology.yaml's own comment on this VM's interfaces): both of
# suscriptor's NICs are baked in at clone time now.
BNG_DIST_SUSCRIPTOR_IP = "10.10.0.9"
BNG_DIST_SUSCRIPTOR_SSH_USER = "labadmin"
BNG_DIST_SUSCRIPTOR_SSH_HOST = BNG_DIST_SUSCRIPTOR_IP

# bng's own real MGMT address (topology.yaml) -- Ubuntu template now
# (was Alpine, back when this VM only ran dnsmasq), so labadmin+sudo
# like every other Ubuntu VM in this lab, not root.
BNG_DIST_BNG_IP = "10.10.0.2"
BNG_DIST_BNG_SSH_USER = "labadmin"
BNG_DIST_BNG_SSH_HOST = BNG_DIST_BNG_IP

# victim's real VLAN_BACKBONE-facing address (shared target VM every
# domain's test scenario uses) -- simulation/bng_subscriber_agent.py's
# own target-ip. NOT victim's MGMT address anymore -- moved on explicit
# direction (docs/vlan-backbone.md): subscriber attack traffic now
# reaches victim by MASQUERADE out bng's own dedicated backbone NIC,
# through pe's OVS bridge (br-ent, OpenFlow-monitored by ryu-manager),
# landing on victim's ENT_DC interface -- not by plain L3 forwarding
# through bng straight onto victim's OOB management interface the way
# it used to. Confirmed on a real run: this is victim_ent_dc_addr in
# deploy/vm-lab's own group_vars, generated from topology.yaml's ENT_DC
# network, same address every other domain's attack traffic now
# converges on too (see docs/vlan-backbone.md's own diagram).
BNG_DIST_TARGET_IP = "10.55.0.100"

# suscriptor's control FIFO (simulation/bng_subscriber_agent.py) --
# same path/protocol simulation/bng_agent.py used.
BNG_DIST_FIFO_PATH = "/run/bng-agent/cmd"

# suscriptor's active-scenario state (simulation/bng_subscriber_agent.
# py's _write_state, written to /run/bng-subscribers/active_scenario.
# json server-side) -- src_ip -> {protocol, dst_port} for whichever
# subscribers are currently attacking. Real RADIUS accounting has no L4
# visibility at all (a volumetric total, not a flow breakdown), so
# telemetry/broadband_adapter.py's distributed-mode collect() merges
# THIS (simulator-known metadata) with FreeRADIUS's real per-session
# byte/packet counters by IP -- same "the synthetic producer already
# knows what it's simulating" convention simulation/ul_traffic_
# simulator.py and the old BNGBlaster-era CSV already used.
#
# Read over a plain local HTTP GET (bng_subscriber_agent.py's own
# _StateHTTPHandler, GET /active_scenario) rather than SSH+cat -- this
# state changes only on attack start/stop, so a fresh SSH connection
# (a real fork/exec + handshake, confirmed ~0.5s) on every collect()
# cycle was pure overhead for reading unchanged bytes almost every
# time. Must match bng_subscriber_agent.py's own _HTTP_PORT constant.
BNG_DIST_SUSCRIPTOR_HTTP_PORT = 8765

# FreeRADIUS's own accounting detail log on `bng` -- ONE flat-text
# record per Access-Accept/Accounting-Start/-Interim-Update/-Stop
# packet, under a per-NAS-client subdirectory (named by the CLIENT's
# real source IP -- confirmed on a real run this is bng_access_addr,
# NOT 127.0.0.1: accel-ppp's own [radius] nas-ip-address directive
# makes it bind() its outgoing RADIUS socket to its real access-side
# address, so that's the address FreeRADIUS actually sees the packets
# arrive from, and what it names the subdirectory after), one file per
# day (detail-YYYYMMDD) per Ubuntu's stock freeradius package config
# (mods-available/detail's default `filename` directive).
# telemetry/broadband_adapter.py globs for `detail-*` under this
# directory and reads the most recent one rather than hardcoding
# today's date, so a slightly different rotation scheme still works.
BNG_DIST_FREERADIUS_DETAIL_DIR = "/var/log/freeradius/radacct/10.20.0.1"

# accel-ppp's own CLI control port (roles/bng's accel-ppp.conf.j2 [cli]
# tcp=127.0.0.1:2000) -- used to resolve src_ip -> username/MAC for
# apply_mitigation() (`accel-cmd -p <port> show sessions`) and to
# terminate a session (`accel-cmd -p <port> terminate username <name>`).
# Reached over SSH to `bng` itself, then locally against loopback there
# (no route from orchestrator to bng's loopback, same as every other
# "control socket only exists on that VM" case in this project).
BNG_DIST_ACCEL_CMD_PORT = 2000

# FreeRADIUS `users` file -- the accept-all posture lives in
# sites-available/default's authorize{} unlang (roles/bng's own tasks),
# not a DEFAULT line here. apply_mitigation()'s persistent block adds a
# per-MAC `Auth-Type := Reject` entry here instead (matched by
# Calling-Station-Id, since roles/bng's tasks also set the `files`
# module's `key` directive to that -- every IPoE subscriber shares the
# same User-Name, so matching on it wouldn't work) so a blocked
# subscriber's re-DHCP (accel-ppp retries this on its own, same lesson
# BNGBlaster's own periodic re-DHCP taught -- session-stop/terminate
# alone gets silently undone) keeps failing auth until unblocked.
BNG_DIST_FREERADIUS_USERS_PATH = "/etc/freeradius/3.0/users"
