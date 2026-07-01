"""
ul_traffic_simulator.py — O-RAN multidomain DDoS proposal.

Replaces ns-3/FlexRIC as the mobile-domain telemetry source. Real
uplink data was never reachable end-to-end in that pipeline: ns-3's
live E2/KPM reporting (BuildRicIndicationMessageDu/AddDuUePmItem) only
ever sends DOWNLINK metrics, the one real UL field that exists in
ns-3's code (pDCPBytesUL, via PF_Container/OCuUpContainerValues) is
dead code never called from the live path AND isn't even part of
FlexRIC's own KPM v3.00 ASN.1 grammar, and the per-UE named-measurement
path that DOES carry real values is itself broken by an ASN.1 schema
mismatch between ns-3's bundled e2sim-kpmv3 and FlexRIC's own KPM v3.00
codegen (see oran_e2_pipeline_status -- a CHOICE extension-marker
position difference that corrupts every measurement after the first
one per UE).

Given the actual deliverable is the controller's detection/correlation/
decision/orchestration logic treating the mobile domain as a real
client -- not validating ns-3's O-RAN stack itself -- this generates
synthetic but realistic per-UE UL telemetry directly in the format
telemetry/mobile_adapter.py's MobileNetworkAdapter already consumes,
and appends it to the canonical CSV path
(MobileNetworkAdapter.DEFAULT_KPM_CSV_PATH) at a real-time pace, the
same role a live xApp would play. Run this alongside ryu-manager
exactly like simulation/run_oran_e2_test.sh's output used to be
consumed -- nothing downstream (correlation, detection, decision,
mitigation dispatch) changes; only the telemetry source does.

Writes the extended CSV format MobileNetworkAdapter._CSV_COLUMNS_EXT
expects (adds dst_port/protocol columns) -- real KPM has no L4
visibility to supply those (see that module's comments), but this
synthetic producer already knows what it's simulating, so it tags each
UE's traffic with the protocol its scenario calls for. That's what lets
DDoSDetectionEngine actually classify SYN_FLOOD/ICMP_FLOOD/DDOS_
DISTRIBUTED for the mobile domain instead of everything defaulting to
UDP_FLOOD.

Usage:
  python3 simulation/ul_traffic_simulator.py
  python3 simulation/ul_traffic_simulator.py --scenario syn_flood
  python3 simulation/ul_traffic_simulator.py --scenario distributed_syn --tick 0.5
  python3 simulation/ul_traffic_simulator.py --interactive
"""

# === Calibración tesis (2026-06-26) ===
# - PRB/SINR diferenciado por protocolo (fix #1)
# - Modelo de tráfico benigno bursty/lognormal con skew positivo (fix #2)
# - Rampa warm-up/cool-down configurable (fix #3)
# - Columnas extended-kpms opcionales (fix #4)
# - attack_mbps recalibrado por protocolo (fix #5)

import argparse
import contextlib
import csv
import json
import random
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))
import config.settings as settings  # noqa: E402 -- needs REPO_DIR on sys.path first

DEFAULT_CSV_PATH = "/tmp/ddos_xapp_events.csv"
DEFAULT_UE_IP_MAP_PATH = REPO_DIR / "config" / "ue_ip_map.csv"
# Must match telemetry/mobile_adapter.py's DEFAULT_RC_COMMAND_QUEUE_PATH --
# not imported from there to avoid pulling in telemetry/__init__.py's
# OpenFlowAdapter import (and its ryu dependency) into this standalone
# simulator process.
DEFAULT_RC_COMMAND_QUEUE_PATH = "/tmp/oran_rc_commands.jsonl"

# Output column order -- must match telemetry/mobile_adapter.py's
# _CSV_COLUMNS_EXT exactly (base KPM columns, then dst_port, protocol).
# Mutated in place (module-global swap, not a new name) by main()/
# run_interactive() when --extended-kpms is given -- _run_tick_loop reads
# this name directly and its signature must not change (interface with
# other call sites), so toggling what it points at before the loop
# starts is the only way to add columns without touching it.
_CSV_COLUMNS = ["timestamp", "imsi", "gnb_id", "dst_ip", "ul_thr_mbps",
                "prb_usage_pct", "sinr_db", "state", "dst_port", "protocol"]

# --extended-kpms appends these two. Both are synthetic-only fields with
# no direct equivalent in E2SM-KPM v3.00's standardized measurement set --
# real KPM has no connection/dwell-time or inter-packet-arrival counter,
# so a real producer (simulation/parse_xapp_kpm_log.py) could never emit
# them; only this synthetic one, which already knows ul_thr_mbps/dst_ip
# per tick, can derive them. MobileNetworkAdapter is never updated to
# read them (nothing in TelemetryEvent models them yet) -- they exist for
# offline thesis analysis, not the live
# detection path. See UE.sample()'s connected_ticks/pkt_interval_ms
# comments for how each is derived.
_CSV_COLUMNS_EXTENDED_KPMS = ["connected_ticks", "pkt_interval_ms"]
_CSV_COLUMNS_BASE = list(_CSV_COLUMNS)

# Same assumed average packet size telemetry/mobile_adapter.py uses to
# convert ul_thr_mbps into an approximate pps figure (ASSUMED_AVG_
# PACKET_SIZE_BYTES) -- kept in sync by convention, not by import, since
# this process deliberately avoids importing telemetry/__init__.py's ryu
# dependency chain (see DEFAULT_RC_COMMAND_QUEUE_PATH's comment above).
_ASSUMED_AVG_PACKET_SIZE_BYTES = 512
# Sentinel for pkt_interval_ms when there's effectively no traffic (pps
# estimate is 0) -- "an extremely long time between packets", not a
# division-by-zero crash or a misleading 0.0 (which would read as
# "packets arriving constantly", the opposite of what's being recorded).
_MAX_PKT_INTERVAL_MS = 999_999.0


class UE:
    """
    One simulated UE's UL behavior over time.

    baseline_mbps/jitter_mbps : normal traffic, a noisy sine-ish wobble
                                 around baseline -- not flat, so a real
                                 attack visibly stands out rather than
                                 just being "the one nonzero number".
    attack_window              : (start_tick, end_tick) or None -- while
                                 inside this window, throughput jumps to
                                 attack_mbps.
    protocol/dst_port          : tagged on every sample, attack or not --
                                 real KPM has no L4 visibility to supply
                                 these (see mobile_adapter.py), but this
                                 synthetic UE already knows what it's
                                 playing, so DDoSDetectionEngine can
                                 actually classify it instead of every
                                 mobile-domain flow defaulting to UDP.
    ramp_ticks                 : warm-up/cool-down length, in ticks, at
                                 the start/end of attack_window -- a real
                                 flood doesn't jump to full rate in one
                                 sample, and ramping makes the CSV's step
                                 less of a free, trivially-detectable
                                 "the threshold crossed instantly" tell.
    """

    def __init__(
        self,
        imsi: int,
        ip: str,
        gnb_id: str = "00101-1",  # PLMN(001/01)-nbID 1 -- see _gnb_for below
        baseline_mbps: float = 0.8,
        jitter_mbps: float = 0.3,
        normal_dst_ip: str = "203.0.113.10",
        attack_window=None,
        attack_mbps: float = 45.0,
        attack_target_ip: str = "10.0.2.10",
        protocol: str = "UDP",
        dst_port: int = 0,
        benign_protocol: str = "UDP",
        benign_dst_port: int = 0,
        ramp_ticks: int = 3,
    ):
        self.imsi = imsi
        self.ip = ip
        self.gnb_id = gnb_id
        self.baseline_mbps = baseline_mbps
        self.jitter_mbps = jitter_mbps
        # protocol/dst_port (below) are the ATTACK-time tag only --
        # benign_protocol/benign_dst_port are what this UE reports the
        # rest of the time, including right after an attack stops. Without
        # this split, a UE that was ever configured as e.g. a TCP_SYN
        # attacker would keep reporting its *normal* baseline traffic
        # tagged "TCP_SYN" forever after -- and since SYN_THRESHOLD=10pps
        # is far below typical benign baseline pps, the next pipeline
        # cycle would misclassify ordinary background traffic as a brand
        # new SYN_FLOOD (observed: every UE that had ever attacked kept
        # re-triggering SYN_FLOOD detections/blocks indefinitely after the
        # real attack had already stopped).
        self.benign_protocol = benign_protocol
        self.benign_dst_port = benign_dst_port
        # A UE's normal UL traffic goes to whatever it's actually
        # talking to out on the internet -- not modeled per-flow here,
        # just a placeholder external IP so benign samples still carry
        # a real (if arbitrary) dst_ip rather than "*". The attack
        # target, by contrast, is deliberately one of this repo's own
        # Mininet ring topology hosts (topologies/ring_topology.py
        # assigns 10.0.{1..4}.10) -- so a real demo could one day have
        # OpenFlow's own telemetry see the same destination and let
        # MultidomainCorrelator actually combine both domains' views of
        # the same attack, instead of the mobile domain's report being
        # an island.
        self.normal_dst_ip = normal_dst_ip
        self.attack_window = attack_window
        self.attack_mbps = attack_mbps
        self.attack_target_ip = attack_target_ip
        self.protocol = protocol
        self.dst_port = dst_port
        self.ramp_ticks = ramp_ticks

        # Benign-traffic burst state (see _sample_benign_mbps) -- last
        # tick (inclusive) this UE is still inside a burst; -1 means not
        # currently bursting.
        self._burst_until_tick = -1

        # connected_ticks state (see sample()'s tail) -- consecutive
        # ACTIVE ticks toward the SAME dst_ip, reset on IDLE or a dst_ip
        # change.
        self._connected_ticks = 0
        self._last_active_dst_ip = None

        # Wall-clock timestamp until which this UE is quarantined (None ==
        # not throttled). Set by apply_throttle() when a "block"/
        # "rate_limit" MitigationAction for this IMSI comes off the RC
        # command queue, cleared automatically once time.time() passes it
        # -- mirrors a real E2SM-RC slicing control (see Option 1 in the
        # O-RAN/FlexRIC investigation: moving the UE into a near-zero-PRB
        # quarantine slice) without actually requiring a live FlexRIC/E2
        # connection, consistent with this simulator's whole reason for
        # existing (see module docstring).
        self.throttled_until = None

    def is_attacking(self, tick: int) -> bool:
        return self.attack_window is not None and self.attack_window[0] <= tick < self.attack_window[1]

    def is_throttled(self) -> bool:
        return self.throttled_until is not None and time.time() < self.throttled_until

    def apply_throttle(self, duration: float) -> None:
        self.throttled_until = time.time() + duration

    def _ramp_factor(self, tick: int) -> float:
        """
        Linear warm-up/cool-down multiplier in [0, 1] applied to the gap
        between baseline_mbps and attack_mbps -- 1.0 means "fully ramped
        (or ramping doesn't apply)", 0.0 means "still at baseline".
        Doesn't touch is_attacking()/attack_window -- purely an internal
        shaping of the rate sample() computes while already inside the
        window.

        Short-circuits to 1.0 (no ramp) when ramp_ticks<=0 or there's
        no attack_window to ramp against (e.g. interactive mode's "until
        stopped" window has no known end tick, so only the warm-up half
        is meaningful there).
        """
        if self.ramp_ticks <= 0 or self.attack_window is None:
            return 1.0
        start, end = self.attack_window
        elapsed = tick - start
        remaining = end - tick
        warm_up = 1.0 if elapsed >= self.ramp_ticks else (elapsed + 1) / self.ramp_ticks
        cool_down = 1.0 if remaining > self.ramp_ticks else remaining / self.ramp_ticks
        return max(0.0, min(warm_up, cool_down))

    # Per-protocol radio degradation profile applied while attacking.
    # PRB usage and SINR scale with how
    # close ul_thr_mbps (itself already shaped by _ramp_factor) is to
    # sat_mbps, instead of a flat 85-100%/2-6dB regardless of actual
    # rate -- a 0.5 Mbps TCP SYN flood's bare-SYN packets occupy a small
    # fraction of the resource blocks a 45 Mbps UDP volumetric flood
    # would saturate; modeling both identically wasn't physically
    # credible. sat_mbps is calibrated near each protocol's own
    # recalibrated attack_mbps default (see SCENARIOS' threshold-margin
    # comment below), not an arbitrary ceiling.
    _ATTACK_RADIO_PROFILES = {
        "UDP":     dict(sat_mbps=45.0, prb_floor=85.0, prb_ceiling=100.0, sinr_floor=2.0,  sinr_ceiling=6.0),
        "TCP_SYN": dict(sat_mbps=1.0,  prb_floor=15.0, prb_ceiling=30.0,  sinr_floor=10.0, sinr_ceiling=18.0),
        "ICMP":    dict(sat_mbps=3.0,  prb_floor=20.0, prb_ceiling=40.0,  sinr_floor=8.0,  sinr_ceiling=15.0),
    }

    # Benign UL traffic model -- bursty + heavy-tailed instead of the old
    # smooth sine wobble, closer to real mobile HTTP/video traffic: short
    # bursts of elevated throughput (BENIGN_BURST_TICKS ticks) separated
    # by quieter stretches, each multiplicatively scaled by a lognormal
    # variable (always >= 0, right-skewed by construction -- occasional
    # sharp peaks, valleys that never go far below baseline) instead of
    # the old symmetric sin()+uniform noise. jitter_mbps still drives how
    # variable a given UE is (used as the lognormal sigma directly,
    # clamped to a sane range), so existing per-UE jitter_mbps values
    # keep meaning instead of becoming a no-op.
    _BENIGN_BURST_PROBABILITY = 0.08   # per-tick chance of starting a burst while idle
    _BENIGN_BURST_TICKS = (3, 5)       # inclusive tick-length range of a burst
    _BENIGN_BURST_MU = 0.5             # bursts run hotter on average, not just noisier

    # Hard ceiling on benign output, comfortably under UDP_THRESHOLD's
    # ~0.82 Mbps equivalent -- benign traffic's default protocol tag is
    # "UDP" (benign_protocol), so that's the threshold it would compete
    # against. A lognormal's right tail is unbounded by construction:
    # without this cap, a large-enough (if individually rare) burst
    # sample eventually clears the threshold purely by chance, with no
    # attack ever configured -- confirmed: 15 idle UEs free-running for a
    # few minutes produced repeated "UDP_FLOOD" detections, ~0.4% of
    # samples (200k-sample check) landing above 0.82 Mbps. This caps the
    # tail without removing it -- bursts can still run several times
    # hotter than baseline, just never past a level real benign traffic
    # plausibly reaches anyway.
    _BENIGN_MAX_MBPS = 0.6

    def _sample_benign_mbps(self, tick: int) -> float:
        idle_sigma = min(0.6, max(0.05, self.jitter_mbps))
        burst_sigma = idle_sigma + 0.15
        if self._burst_until_tick >= tick:
            mbps = self.baseline_mbps * random.lognormvariate(self._BENIGN_BURST_MU, burst_sigma)
        elif random.random() < self._BENIGN_BURST_PROBABILITY:
            self._burst_until_tick = tick + random.randint(*self._BENIGN_BURST_TICKS) - 1
            mbps = self.baseline_mbps * random.lognormvariate(self._BENIGN_BURST_MU, burst_sigma)
        else:
            mbps = self.baseline_mbps * random.lognormvariate(0.0, idle_sigma)
        return min(self._BENIGN_MAX_MBPS, max(0.0, mbps))

    def sample(self, tick: int) -> dict:
        if self.is_throttled():
            # Quarantine-slice effect: scheduler starves the UE down to
            # near-zero PRBs regardless of whether it's mid-attack -- this
            # is what actually stops the flood, not a channel-quality
            # change, so SINR stays in its normal range.
            ul_thr_mbps = random.uniform(0.0, 0.01)
            prb_usage_pct = random.uniform(0.0, 1.0)
            sinr_db = random.uniform(15.0, 25.0)
            state = "ACTIVE"
            attacking_now = self.is_attacking(tick)
            dst_ip = self.attack_target_ip if attacking_now else self.normal_dst_ip
            protocol = self.protocol if attacking_now else self.benign_protocol
            dst_port = self.dst_port if attacking_now else self.benign_dst_port
        elif self.is_attacking(tick):
            target_mbps = self.attack_mbps * random.uniform(0.9, 1.1)
            ramp = self._ramp_factor(tick)
            ul_thr_mbps = max(0.0, self.baseline_mbps + (target_mbps - self.baseline_mbps) * ramp)
            profile = self._ATTACK_RADIO_PROFILES.get(self.protocol, self._ATTACK_RADIO_PROFILES["UDP"])
            saturation = min(ul_thr_mbps / profile["sat_mbps"], 1.0) if profile["sat_mbps"] > 0 else 1.0
            prb_usage_pct = profile["prb_floor"] + (profile["prb_ceiling"] - profile["prb_floor"]) * saturation
            prb_usage_pct = min(100.0, max(0.0, prb_usage_pct + random.uniform(-2.0, 2.0)))
            sinr_db = profile["sinr_ceiling"] - (profile["sinr_ceiling"] - profile["sinr_floor"]) * saturation
            sinr_db = max(0.1, sinr_db + random.uniform(-1.0, 1.0))
            state = "ACTIVE"
            dst_ip = self.attack_target_ip
            protocol = self.protocol
            dst_port = self.dst_port
        else:
            ul_thr_mbps = self._sample_benign_mbps(tick)
            prb_usage_pct = min(100.0, max(0.0, 5.0 + ul_thr_mbps * 3.0))
            sinr_db = random.uniform(15.0, 25.0)
            state = "ACTIVE" if ul_thr_mbps > 0.05 else "IDLE"
            dst_ip = self.normal_dst_ip
            protocol = self.benign_protocol
            dst_port = self.benign_dst_port

        assert 0.0 <= prb_usage_pct <= 100.0, f"prb_usage_pct out of range: {prb_usage_pct}"
        assert sinr_db > 0.0, f"sinr_db out of range: {sinr_db}"

        # connected_ticks: consecutive ACTIVE ticks toward the SAME
        # dst_ip -- proxy for "DRB hold duration" (see __init__'s
        # comment). Tracked unconditionally (cheap); only written to the
        # CSV when --extended-kpms swaps in _CSV_COLUMNS_EXTENDED_KPMS.
        if state == "ACTIVE" and dst_ip == self._last_active_dst_ip:
            self._connected_ticks += 1
        elif state == "ACTIVE":
            self._connected_ticks = 1
        else:
            self._connected_ticks = 0
        self._last_active_dst_ip = dst_ip if state == "ACTIVE" else None

        # pkt_interval_ms: mean inter-packet gap implied by ul_thr_mbps at
        # the same ASSUMED_AVG_PACKET_SIZE_BYTES the rest of this pipeline
        # already assumes (pps = bps / 512, see mobile_adapter.py) --
        # 1000/pps, not pps itself.
        pps_est = (ul_thr_mbps * 1e6 / 8.0) / _ASSUMED_AVG_PACKET_SIZE_BYTES
        pkt_interval_ms = (1000.0 / pps_est) if pps_est > 0 else _MAX_PKT_INTERVAL_MS

        return {
            "timestamp": f"{time.time():.6f}",
            "imsi": str(self.imsi),
            "gnb_id": self.gnb_id,
            "dst_ip": dst_ip,
            "ul_thr_mbps": f"{ul_thr_mbps:.6f}",
            "prb_usage_pct": f"{prb_usage_pct:.3f}",
            "sinr_db": f"{sinr_db:.3f}",
            "state": state,
            "dst_port": str(dst_port),
            "protocol": protocol,
            "connected_ticks": str(self._connected_ticks),
            "pkt_interval_ms": f"{pkt_interval_ms:.3f}",
        }


# config/settings.py thresholds each scenario is tuned against (so the
# attack magnitude is always comfortably past the threshold that
# classifies it, with margin -- not just barely over):
#   SYN_THRESHOLD=10 pps  -> ~0.041 Mbps  (TCP_SYN)
#   UDP_THRESHOLD=200 pps -> ~0.82 Mbps   (UDP)
#   ICMP_THRESHOLD=150pps -> ~0.61 Mbps   (ICMP)
#   DIST_MIN_SOURCES=5, DIST_ENTROPY_THRESHOLD=0.7 (near-equal per-source rate)
# via MobileNetworkAdapter's pps = bps / ASSUMED_AVG_PACKET_SIZE_BYTES(512).
#
# Calibración tesis (2026-06-26, fix #5) -- recalibrated attack_mbps
# defaults below: a single mobile UE sustaining 3 Mbps of bare TCP SYNs
# (the old default) is ~73k SYN/s at a 40-byte packet, not a credible
# single-handset flood for the thesis narrative. New defaults, still
# comfortably classified (worst case at the existing ±10% sampling
# jitter in sample(), i.e. the low end of that range):
#   scenario_syn_flood:        0.5 Mbps  -> ~122.07 pps (×12.2 over SYN_THRESHOLD=10,
#                               worst case ~109.9 pps at -10% jitter)
#   scenario_icmp_flood:       1.5 Mbps  -> ~366.21 pps (×2.44 over ICMP_THRESHOLD=150,
#                               worst case ~329.6 pps at -10% jitter -- still >150;
#                               ICMP_THRESHOLD itself left unchanged, margin checked
#                               sufficient)
#   scenario_distributed_syn:  0.4 Mbps/UE x 5 UEs = 2.0 Mbps total -> ~97.66 pps/UE,
#                               ~488.3 pps aggregate (entropy unaffected -- still equal
#                               per-source rate)
#   scenario_udp_flood:        45.0 Mbps (unchanged -- this IS meant to be the extreme
#                               volumetric case) -> ~10986.3 pps (×54.9 over UDP_THRESHOLD=200)

_BENIGN_UES = [
    dict(imsi=1, ip="10.60.0.2", baseline_mbps=0.3, jitter_mbps=0.15, normal_dst_ip="203.0.113.10"),
    dict(imsi=2, ip="10.60.0.3", baseline_mbps=0.4, jitter_mbps=0.15, normal_dst_ip="203.0.113.20"),
]


# FlexRIC's E2 node identity (global_e2_node_id_t, src/lib/e2ap/v3_01/
# e2ap_types/common/e2ap_global_node_id.h) is PLMN (MCC/MNC, plain
# integers -- e2ap_plmn_t) + a numeric gNB ID (e2ap_gnb_id_t.nb_id,
# uint32_t). FlexRIC itself never formats this as one string -- its
# example xApps print mcc/mnc/nb_id as separate fields (examples/xApp/c/
# helloworld/hw.c) -- but a single CSV column needs one, so this uses the
# common real-world "PLMN-nbID" convention (e.g. "00101-1") instead of a
# bare counter. MCC=001/MNC=01 is the well-known generic test PLMN used
# across RAN testbeds (srsRAN, OAI, etc.), not a real operator's.
_TEST_MCC = "001"
_TEST_MNC = "01"


def _gnb_for(index: int, gnb_count: int) -> str:
    """Round-robins UEs across gnb_count simulated gNBs
    ("<mcc><mnc>-1".."<mcc><mnc>-gnb_count") by creation order -- e.g.
    with gnb_count=3, UE 0/3/6/... land on gNB "00101-1", UE 1/4/7/... on
    "00101-2", UE 2/5/8/... on "00101-3". gnb_count=1 (the default
    everywhere) keeps every UE on "00101-1", unchanged unless the caller
    explicitly asks for more."""
    nb_id = (index % max(gnb_count, 1)) + 1
    return f"{_TEST_MCC}{_TEST_MNC}-{nb_id}"


def _benign_ues(gnb_count: int = 1):
    # Distinct normal_dst_ip per UE -- MultidomainCorrelator groups by
    # dst_ip, so benign UEs sharing one placeholder destination would
    # have their otherwise-individually-safe pps summed together and
    # could cross a threshold as a false multi-source flood, which isn't
    # what's being simulated here.
    return [
        UE(gnb_id=_gnb_for(i, gnb_count), **kwargs)
        for i, kwargs in enumerate(_BENIGN_UES)
    ]


def scenario_udp_flood(attack_end_tick: int, gnb_count: int = 1):
    """Single UE, UDP volumetric flood -- the original/default scenario."""
    ues = _benign_ues(gnb_count)
    ues.append(UE(
        imsi=3, ip="10.60.0.4", baseline_mbps=0.3, jitter_mbps=0.1, normal_dst_ip="203.0.113.30",
        attack_window=(10, attack_end_tick), attack_mbps=45.0, protocol="UDP",
        gnb_id=_gnb_for(len(ues), gnb_count),
    ))
    return ues


def scenario_syn_flood(attack_end_tick: int, gnb_count: int = 1):
    """Single UE, TCP SYN flood toward a typical web port."""
    ues = _benign_ues(gnb_count)
    ues.append(UE(
        imsi=3, ip="10.60.0.4", baseline_mbps=0.3, jitter_mbps=0.1, normal_dst_ip="203.0.113.30",
        attack_window=(10, attack_end_tick), attack_mbps=0.5,
        protocol="TCP_SYN", dst_port=443,
        gnb_id=_gnb_for(len(ues), gnb_count),
    ))
    return ues


def scenario_icmp_flood(attack_end_tick: int, gnb_count: int = 1):
    """Single UE, ICMP flood."""
    ues = _benign_ues(gnb_count)
    ues.append(UE(
        imsi=3, ip="10.60.0.4", baseline_mbps=0.3, jitter_mbps=0.1, normal_dst_ip="203.0.113.30",
        attack_window=(10, attack_end_tick), attack_mbps=1.5,
        protocol="ICMP", dst_port=0,
        gnb_id=_gnb_for(len(ues), gnb_count),
    ))
    return ues


def scenario_distributed_syn(attack_end_tick: int, gnb_count: int = 1):
    """
    Five UEs (>= settings.DIST_MIN_SOURCES), each contributing a near-
    equal TCP_SYN rate toward the same target -- the near-uniform
    per-source distribution (high entropy) is what makes
    DDoSDetectionEngine classify this as DDOS_DISTRIBUTED instead of
    five independent SYN_FLOOD attackers. Spread across gnb_count gNBs
    (round-robin) when given more than one -- a distributed attack
    coming from several gNBs at once is the realistic case; gnb_count=1
    keeps them all on gNB 1.
    """
    ues = _benign_ues(gnb_count)
    for i in range(5):
        ues.append(UE(
            imsi=10 + i, ip=f"10.60.0.{20 + i}",
            baseline_mbps=0.3, jitter_mbps=0.1, normal_dst_ip=f"203.0.113.{40 + i}",
            attack_window=(10, attack_end_tick), attack_mbps=0.4,
            protocol="TCP_SYN", dst_port=443,
            gnb_id=_gnb_for(len(ues), gnb_count),
        ))
    return ues


SCENARIOS = {
    "udp_flood": scenario_udp_flood,
    "syn_flood": scenario_syn_flood,
    "icmp_flood": scenario_icmp_flood,
    "distributed_syn": scenario_distributed_syn,
}


def read_new_commands(path: str, offset: int) -> tuple:
    """
    Tails MobileNetworkAdapter.apply_mitigation()'s JSONL command queue,
    same offset-tracking pattern MobileNetworkAdapter.collect() uses on
    the KPM CSV -- returns (commands, new_offset). Missing file (queue
    not created yet) is not an error, same convention as
    oran_bridge/ue_ip_map.py.
    """
    if not Path(path).exists():
        return [], offset

    commands = []
    with open(path, "r") as f:
        f.seek(offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                commands.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        new_offset = f.tell()
    return commands, new_offset


def write_ue_ip_map(ues, path: Path):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["imsi", "ip"])
        for ue in ues:
            writer.writerow([ue.imsi, ue.ip])


def _consume_rc_commands(ues_by_imsi: dict, rc_command_queue: str, rc_command_offset: int) -> int:
    """
    Applies any new throttle/unblock commands off the RC queue to the
    matching UEs. Returns the new read offset. Not printed -- the
    controller already reports both through its own MITIGATION
    dashboard/logger line (ryu_controller_2.py's _run_pipeline); this
    process only needs to apply the effect, the same way a real RAN
    wouldn't echo a RIC CONTROL REQUEST back as a log.
    """
    commands, new_offset = read_new_commands(rc_command_queue, rc_command_offset)
    for command in commands:
        ue = ues_by_imsi.get(command.get("imsi"))
        if ue is None:
            continue
        if command.get("action") == "unblock":
            # Lifts the quarantine immediately rather than extending it --
            # an "unblock" with a leftover duration field would otherwise
            # be treated like another throttle command below.
            ue.throttled_until = None
            continue
        ue.apply_throttle(command.get("duration", 60))
    return new_offset


def _run_tick_loop(
    ues: list,
    out_csv: str,
    rc_command_queue: str,
    tick_seconds: float,
    duration: float = 0.0,
    verbose: bool = True,
    stop_event: "threading.Event | None" = None,
    ues_lock: "threading.Lock | None" = None,
):
    """
    The actual sampling loop: every tick_seconds, consume pending RC
    commands, sample every UE, and append one row per UE to out_csv.
    Shared by the scripted (--scenario) entry point and the interactive
    mode's background thread -- stop_event lets the interactive mode
    end this from another thread without relying on KeyboardInterrupt
    (which only the main thread receives).

    ues_lock: held for the whole per-tick sampling pass when given
    (interactive mode only). Without it, the interactive menu's thread
    can mutate a UE's attack_window/protocol/etc. *while* this thread is
    midway through sampling that same tick's batch -- e.g. the menu
    clears attack_window for UEs 1-5 on "stop", but this loop already
    sampled UE 1 as still attacking before the mutation landed and only
    then samples UEs 2-5 as already reverted. That leaves UE 1's active
    block one confirm-cycle behind the other four's, and if the
    interactive session exits before that extra cycle completes, UE 1's
    quarantine never gets confirmed-unblocked at all (observed: 4 of 5
    UEs in a group attack correctly unblocked, the 5th left blocked
    forever after the simulator process exited). Locking the whole
    per-tick batch makes "all UEs sampled" and "the menu's mutation"
    mutually exclusive, so a tick is never split across the change.
    """
    ues_by_imsi = {ue.imsi: ue for ue in ues}
    tick = 0
    start = time.time()
    rc_command_offset = 0
    # Tracks each UE's attacking/not-attacking state across ticks so a
    # transition (false->true or true->false) can be logged with a
    # timestamp -- this fires for BOTH modes: the scripted mode's
    # automatic attack_window start/end, and the interactive mode's
    # manual attack-config/"stop" (which just flips attack_window, picked
    # up here on the very next tick). Printed unconditionally (not gated
    # by `verbose`) since this is exactly the line meant to be grepped
    # against the controller's own "%Y-%m-%d %H:%M:%S ... ATTACK
    # DETECTED/MITIGATION" lines to correlate the two processes' clocks.
    attacking_state = {ue.imsi: False for ue in ues}

    with open(out_csv, "a", newline="") as f:
        writer = csv.writer(f)
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            if duration > 0 and (time.time() - start) >= duration:
                return

            rc_command_offset = _consume_rc_commands(ues_by_imsi, rc_command_queue, rc_command_offset)

            with ues_lock if ues_lock is not None else contextlib.nullcontext():
                for ue in ues:
                    row = ue.sample(tick)
                    writer.writerow([row[c] for c in _CSV_COLUMNS])

                    now_attacking = ue.is_attacking(tick)
                    was_attacking = attacking_state[ue.imsi]
                    if now_attacking and not was_attacking:
                        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        _print_async(f"{now_str} [ul_traffic_simulator] ATTACK START imsi={ue.imsi} "
                                     f"protocol={ue.protocol} target={ue.attack_target_ip}:{ue.dst_port} "
                                     f"mbps={ue.attack_mbps}")
                    elif was_attacking and not now_attacking:
                        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        _print_async(f"{now_str} [ul_traffic_simulator] ATTACK END imsi={ue.imsi} "
                                     f"protocol={ue.protocol} target={ue.attack_target_ip}:{ue.dst_port}")
                    attacking_state[ue.imsi] = now_attacking

                    if verbose:
                        flag = f" [ATTACK -> {row['dst_ip']}]" if ue.is_attacking(tick) else f" -> {row['dst_ip']}"
                        # Same "%Y-%m-%d %H:%M:%S" format ryu_controller_2.py's
                        # logging.basicConfig uses, so a line here and the
                        # controller's own log line for the same event can be
                        # matched up directly without converting formats by hand.
                        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        print(f"{now_str} tick={tick} imsi={ue.imsi} ul_thr_mbps={row['ul_thr_mbps']} "
                              f"prb={row['prb_usage_pct']}%{flag}")
            f.flush()
            tick += 1

            if stop_event is not None:
                stop_event.wait(tick_seconds)
            else:
                time.sleep(tick_seconds)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interactive", action="store_true",
                         help="prompt for UE count and attacks at runtime instead of --scenario")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="udp_flood",
                         help="attack pattern to simulate (default: udp_flood)")
    parser.add_argument("--tick", type=float, default=2.0, help="seconds between samples")
    parser.add_argument("--duration", type=float, default=0.0, help="total seconds to run, 0 = forever")
    parser.add_argument("--out-csv", default=DEFAULT_CSV_PATH)
    parser.add_argument("--ue-ip-map", default=str(DEFAULT_UE_IP_MAP_PATH))
    parser.add_argument("--no-attack", action="store_true", help="disable the scenario's attack window(s)")
    parser.add_argument("--attack-end-tick", type=int, default=25,
                         help="tick at which the attack stops on its own")
    parser.add_argument("--gnb-count", type=int, default=1,
                         help="number of simulated gNBs to round-robin UEs across (default: 1)")
    parser.add_argument("--rc-command-queue", default=str(DEFAULT_RC_COMMAND_QUEUE_PATH),
                         help="JSONL queue MobileNetworkAdapter.apply_mitigation() writes to")
    parser.add_argument("--extended-kpms", action="store_true",
                         help="append connected_ticks/pkt_interval_ms synthetic columns "
                              "(no E2SM-KPM v3 equivalent -- see _CSV_COLUMNS_EXTENDED_KPMS)")
    args = parser.parse_args()

    if args.extended_kpms:
        # Module-global swap, not a parameter -- _run_tick_loop's
        # signature can't change (see _CSV_COLUMNS' comment), and it
        # reads this name directly, so this must happen before it's
        # started, in both the scripted and interactive entry points.
        global _CSV_COLUMNS
        _CSV_COLUMNS = _CSV_COLUMNS_BASE + _CSV_COLUMNS_EXTENDED_KPMS

    if args.interactive:
        return run_interactive(args)

    ues = SCENARIOS[args.scenario](args.attack_end_tick, args.gnb_count)
    if args.no_attack:
        for ue in ues:
            ue.attack_window = None

    write_ue_ip_map(ues, Path(args.ue_ip_map))
    print(f"[ul_traffic_simulator] scenario={args.scenario}")
    print(f"[ul_traffic_simulator] wrote {len(ues)} UE(s) to {args.ue_ip_map}")

    # Truncate leftover state from a previous run -- MobileNetworkAdapter
    # always starts tailing out-csv from byte 0 when ryu-manager (re)starts,
    # so stale attack-magnitude rows from an earlier session would otherwise
    # be read as live telemetry on the very first collect() cycle, before
    # this run has written anything itself (observed: a UDP_FLOOD detection
    # and BLOCK firing seconds after ryu-manager started, well before this
    # run's own attack_window even began). Same reasoning applies to
    # rc-command-queue: a stale "block" line left over from a previous
    # session's throttle would otherwise get replayed against this run's
    # (possibly different) IMSIs.
    Path(args.out_csv).write_text("")
    Path(args.rc_command_queue).write_text("")

    for ue in ues:
        attack_desc = (
            f"{ue.protocol} flood from tick {ue.attack_window[0]}" if ue.attack_window
            else "benign only"
        )
        print(f"  IMSI {ue.imsi} -> {ue.ip} (gNB {ue.gnb_id}) ({attack_desc})")

    print(f"[ul_traffic_simulator] appending to {args.out_csv} every {args.tick}s "
          f"({'forever' if args.duration <= 0 else f'{args.duration}s total'}) -- Ctrl+C to stop")

    try:
        _run_tick_loop(ues, args.out_csv, args.rc_command_queue, args.tick, duration=args.duration)
    except KeyboardInterrupt:
        print("\n[ul_traffic_simulator] stopped")


# ============================================================
# Interactive mode
# ============================================================
#
# A background thread runs _run_tick_loop continuously (so telemetry
# keeps flowing the whole session, regardless of whether an attack is
# currently active) while the main thread drives a menu: configure N
# "normal" UEs once, then repeatedly pick an attack type, fill in its
# parameters, let it run, and stop it to choose another -- all within
# one continuous CSV/run, matching what a person actually wants from a
# live demo instead of relaunching the process per attack.

# Text of whatever prompt is currently awaiting input on the main
# thread, if any -- set right before each input() call, cleared right
# after. Read by _print_async (called from the background tick-loop
# thread) so an ATTACK START/END line printed mid-prompt doesn't just
# glue itself onto the end of the visible "Opción [0]: " or "> " text;
# instead it breaks to its own line and redraws the prompt below it, so
# there's always a clean line to type into. A benign race (the main
# thread clearing this a moment after the background thread already
# read it) just means an occasional missed redraw, not a correctness
# issue -- not worth a lock for a cosmetic concern.
_CURRENT_PROMPT = {"text": None}


def _print_async(message: str) -> None:
    prompt_text = _CURRENT_PROMPT["text"]
    if prompt_text:
        print()  # break out of the half-drawn prompt line
        print(message)
        print(prompt_text, end="", flush=True)  # redraw it so there's something to type into
    else:
        print(message)


def _prompt(prompt: str, default: "str | None" = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    text = f"{prompt}{suffix}: "
    _CURRENT_PROMPT["text"] = text
    try:
        raw = input(text).strip()
    finally:
        _CURRENT_PROMPT["text"] = None
    return raw if raw else (default or "")


def _prompt_int(prompt: str, default: int, min_value: "int | None" = None) -> int:
    while True:
        raw = _prompt(prompt, str(default))
        try:
            value = int(raw)
        except ValueError:
            print("  Ingresa un número entero válido.")
            continue
        if min_value is not None and value < min_value:
            print(f"  Debe ser >= {min_value}.")
            continue
        return value


def _prompt_float(prompt: str, default: float) -> float:
    while True:
        raw = _prompt(prompt, str(default))
        try:
            return float(raw)
        except ValueError:
            print("  Ingresa un número válido.")


def build_normal_ues(n: int, gnb_count: int = 1) -> list:
    """N UEs with ordinary, individually-benign background traffic --
    each gets its own normal_dst_ip (see SCENARIOS' "Distinct
    normal_dst_ip" comment for why that matters to the correlator), and
    is round-robin'd across gnb_count simulated gNBs (see _gnb_for)."""
    ues = []
    for i in range(n):
        ues.append(UE(
            imsi=i + 1,
            ip=f"10.60.0.{2 + i}",
            baseline_mbps=round(random.uniform(0.2, 0.5), 2),
            jitter_mbps=0.15,
            normal_dst_ip=f"203.0.113.{10 + i}",
            gnb_id=_gnb_for(i, gnb_count),
        ))
    return ues


_ATTACK_TYPES = {
    "1": ("UDP Flood", "single"),
    "2": ("TCP SYN Flood", "single"),
    "3": ("ICMP Flood", "single"),
    "4": ("Distributed TCP SYN Flood", "distributed"),
}


def _print_menu(ues: list):
    print()
    print("=== Simulador interactivo de tráfico móvil ===")
    print(f"UEs configuradas: {len(ues)} "
          f"({sum(1 for u in ues if u.attack_window)} atacando actualmente)")
    print("Elige un tipo de ataque:")
    print("  1) UDP Flood")
    print("  2) TCP SYN Flood")
    print("  3) ICMP Flood")
    print("  4) Distributed TCP SYN Flood (varios UE como origen)")
    print("  0) Salir")


def _free_ues(ues: list) -> list:
    """UEs not currently part of a running attack -- available to pick from."""
    return [ue for ue in ues if not ue.attack_window]


def _choose_single_attacker(ues: list) -> "UE | None":
    free = _free_ues(ues)
    if not free:
        print("  No hay ninguna UE libre (todas están atacando ya). Detén un ataque primero.")
        return None
    print("  UEs disponibles: " + ", ".join(f"IMSI {u.imsi} (gNB {u.gnb_id})" for u in free))
    while True:
        raw = _prompt("  ¿Qué UE ataca? (IMSI)", str(free[0].imsi))
        matches = [u for u in free if str(u.imsi) == raw]
        if matches:
            return matches[0]
        print("  Esa UE no existe o ya está ocupada -- elige una de la lista.")


def _choose_group(ues: list, min_sources: int, default_count: int) -> "list | None":
    free = _free_ues(ues)
    if len(free) < min_sources:
        print(f"  Solo hay {len(free)} UE(s) libres y este ataque necesita al menos "
              f"{min_sources} para que el detector lo clasifique como tal. "
              f"Detén otro ataque o configura más UEs.")
        if not free:
            return None
    count = _prompt_int(
        f"  ¿Cuántas UEs participan? (mínimo recomendado {min_sources}, libres: {len(free)})",
        default=min(default_count, len(free)) if free else default_count,
    )
    if count > len(free):
        print(f"  Solo hay {len(free)} libres -- se usarán todas.")
        count = len(free)
    if count < min_sources:
        print(f"  Aviso: con {count} UE(s) es posible que el detector NO lo clasifique "
              f"como este tipo de ataque (mínimo recomendado: {min_sources}).")
    return free[:count]


def _configure_attack(ues: list, ues_lock: threading.Lock) -> "tuple[str, list] | None":
    """Prompts for an attack type and its parameters, applies it to the
    chosen UE(s), and returns (description, affected_ues) -- or None if
    the user cancelled / no UE was available. The actual attribute
    mutation (not the prompting, which can block on user input
    indefinitely) is done under ues_lock -- see _run_tick_loop's
    docstring for why a torn mutation across a tick's UE batch leaves a
    block confirm-cycle permanently out of sync with its siblings."""
    while True:
        _print_menu(ues)
        choice = _prompt("Opción", "0")
        if choice == "0":
            return None
        if choice not in _ATTACK_TYPES:
            print("  Opción no válida.")
            continue
        name, kind = _ATTACK_TYPES[choice]
        break

    target_ip = _prompt("  IP objetivo del ataque", "10.0.2.10")

    if kind == "single":
        ue = _choose_single_attacker(ues)
        if ue is None:
            return None
        if choice == "1":  # UDP Flood
            mbps = _prompt_float(
                f"  Throughput de ataque en Mbps (umbral UDP_THRESHOLD={settings.UDP_THRESHOLD}pps)",
                45.0,
            )
            protocol, dst_port = "UDP", 0
        elif choice == "2":  # TCP SYN Flood
            mbps = _prompt_float(
                f"  Throughput de ataque en Mbps (umbral SYN_THRESHOLD={settings.SYN_THRESHOLD}pps)",
                0.5,
            )
            dst_port = _prompt_int("  Puerto TCP objetivo", 443)
            protocol = "TCP_SYN"
        else:  # ICMP Flood
            mbps = _prompt_float(
                f"  Throughput de ataque en Mbps (umbral ICMP_THRESHOLD={settings.ICMP_THRESHOLD}pps)",
                1.5,
            )
            protocol, dst_port = "ICMP", 0
        with ues_lock:
            ue.protocol, ue.dst_port = protocol, dst_port
            ue.attack_mbps = mbps
            ue.attack_target_ip = target_ip
            ue.attack_window = (0, 10 ** 9)  # "until stopped" -- see is_attacking()
        return f"{name} desde IMSI {ue.imsi} (gNB {ue.gnb_id}) -> {target_ip} ({mbps} Mbps)", [ue]

    if kind == "distributed":
        group = _choose_group(ues, settings.DIST_MIN_SOURCES, default_count=5)
        if not group:
            return None
        mbps = _prompt_float("  Throughput de ataque por UE en Mbps", 0.4)
        dst_port = _prompt_int("  Puerto TCP objetivo", 443)
        with ues_lock:
            for ue in group:
                ue.protocol, ue.dst_port = "TCP_SYN", dst_port
                ue.attack_mbps = mbps
                ue.attack_target_ip = target_ip
                ue.attack_window = (0, 10 ** 9)
        imsis = ", ".join(f"{u.imsi}(gNB{u.gnb_id})" for u in group)
        return f"{name} desde {len(group)} UE(s) (IMSI {imsis}) -> {target_ip} ({mbps} Mbps c/u)", group

    return None


def run_interactive(args):
    print("=== Simulador interactivo de tráfico móvil ===")
    n = _prompt_int("¿Cuántas UEs quieres simular con tráfico normal?", default=3, min_value=1)
    gnb_count = _prompt_int(
        "¿Cuántos gNB (estaciones base) quieres simular?",
        default=min(3, n), min_value=1,
    )
    if gnb_count > n:
        print(f"  Aviso: hay menos UEs ({n}) que gNB solicitados ({gnb_count}) -- "
              f"algunos gNB quedarán sin UEs asignadas.")
    ues = build_normal_ues(n, gnb_count)

    write_ue_ip_map(ues, Path(args.ue_ip_map))
    Path(args.out_csv).write_text("")
    Path(args.rc_command_queue).write_text("")
    print(f"[ul_traffic_simulator] {n} UE(s) configuradas en {gnb_count} gNB, tráfico normal:")
    for ue in ues:
        print(f"  IMSI {ue.imsi} -> {ue.ip} (gNB {ue.gnb_id}, baseline {ue.baseline_mbps} Mbps -> {ue.normal_dst_ip})")

    stop_event = threading.Event()
    # Held around every full per-tick UE batch (background thread) and
    # around every attack-config/stop mutation (this thread) -- see
    # _run_tick_loop's docstring for the exact race this closes.
    ues_lock = threading.Lock()
    thread = threading.Thread(
        target=_run_tick_loop,
        args=(ues, args.out_csv, args.rc_command_queue, args.tick),
        kwargs={"verbose": False, "stop_event": stop_event, "ues_lock": ues_lock},
        daemon=True,
    )
    thread.start()
    print(f"[ul_traffic_simulator] generando telemetría cada {args.tick}s en segundo plano "
          f"({args.out_csv})")

    try:
        while True:
            result = _configure_attack(ues, ues_lock)
            if result is None:
                break
            description, attacking_ues = result
            print(f"\n[ul_traffic_simulator] Ataque iniciado: {description}")
            print("Escribe 'stop' y Enter para detenerlo y elegir otro ataque.")
            while True:
                _CURRENT_PROMPT["text"] = "> "
                try:
                    cmd = input("> ").strip().lower()
                finally:
                    _CURRENT_PROMPT["text"] = None
                if cmd == "":
                    # Enter alone is not "stop" -- an accidental keystroke
                    # (or one of the background ATTACK START/END redraws
                    # below) shouldn't end a running attack with no
                    # explicit intent behind it.
                    continue
                if cmd in ("stop", "s"):
                    with ues_lock:
                        for ue in attacking_ues:
                            ue.attack_window = None
                    print("[ul_traffic_simulator] Ataque detenido. Las UEs volvieron a tráfico normal.")
                    break
                print("  Comando no reconocido -- escribe 'stop' para detener el ataque actual.")
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        print("[ul_traffic_simulator] cerrando...")
        stop_event.set()
        thread.join(timeout=2)
        print("[ul_traffic_simulator] stopped")


if __name__ == "__main__":
    sys.exit(main())
