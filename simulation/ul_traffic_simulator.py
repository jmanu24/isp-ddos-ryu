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

Usage:
  python3 simulation/ul_traffic_simulator.py
  python3 simulation/ul_traffic_simulator.py --tick 2 --duration 120
"""

import argparse
import csv
import json
import math
import random
import sys
import time
from datetime import datetime
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CSV_PATH = "/tmp/ddos_xapp_events.csv"
DEFAULT_UE_IP_MAP_PATH = REPO_DIR / "config" / "ue_ip_map.csv"
# Must match telemetry/mobile_adapter.py's DEFAULT_RC_COMMAND_QUEUE_PATH --
# not imported from there to avoid pulling in telemetry/__init__.py's
# OpenFlowAdapter import (and its ryu dependency) into this standalone
# simulator process.
DEFAULT_RC_COMMAND_QUEUE_PATH = "/tmp/oran_rc_commands.jsonl"


class UE:
    """
    One simulated UE's UL behavior over time.

    baseline_mbps/jitter_mbps : normal traffic, a noisy sine-ish wobble
                                 around baseline -- not flat, so a real
                                 attack visibly stands out rather than
                                 just being "the one nonzero number".
    attack_window             : (start_tick, end_tick) or None -- while
                                 inside this window, throughput jumps to
                                 attack_mbps (a UDP-flood-magnitude
                                 value, comfortably past
                                 config/settings.py's UDP_THRESHOLD=200
                                 pps once converted through
                                 MobileNetworkAdapter's
                                 ASSUMED_AVG_PACKET_SIZE_BYTES=512).
    """

    def __init__(
        self,
        imsi: int,
        ip: str,
        gnb_id: str = "1",
        baseline_mbps: float = 0.8,
        jitter_mbps: float = 0.3,
        normal_dst_ip: str = "203.0.113.10",
        attack_window=None,
        attack_mbps: float = 45.0,
        attack_target_ip: str = "10.0.2.10",
    ):
        self.imsi = imsi
        self.ip = ip
        self.gnb_id = gnb_id
        self.baseline_mbps = baseline_mbps
        self.jitter_mbps = jitter_mbps
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
            dst_ip = self.attack_target_ip if self.is_attacking(tick) else self.normal_dst_ip
        elif self.is_attacking(tick):
            ul_thr_mbps = self.attack_mbps * random.uniform(0.9, 1.1)
            prb_usage_pct = min(100.0, random.uniform(85.0, 100.0))
            sinr_db = random.uniform(2.0, 6.0)  # degraded -- channel saturated
            state = "ACTIVE"
            dst_ip = self.attack_target_ip
        else:
            wobble = math.sin(tick / 7.0) * self.jitter_mbps
            ul_thr_mbps = max(0.0, self.baseline_mbps + wobble + random.uniform(-0.05, 0.05))
            prb_usage_pct = min(100.0, max(0.0, 5.0 + ul_thr_mbps * 3.0))
            sinr_db = random.uniform(15.0, 25.0)
            state = "ACTIVE" if ul_thr_mbps > 0.05 else "IDLE"
            dst_ip = self.normal_dst_ip

        return {
            "timestamp": f"{time.time():.6f}",
            "imsi": str(self.imsi),
            "gnb_id": self.gnb_id,
            "dst_ip": dst_ip,
            "ul_thr_mbps": f"{ul_thr_mbps:.6f}",
            "prb_usage_pct": f"{prb_usage_pct:.3f}",
            "sinr_db": f"{sinr_db:.3f}",
            "state": state,
        }


def default_ues(attack_end_tick: int = 25):
    # config/settings.py's UDP_THRESHOLD=200 pps corresponds to
    # ~0.82 Mbps through MobileNetworkAdapter's pps approximation
    # (bps / ASSUMED_AVG_PACKET_SIZE_BYTES=512) -- baseline+jitter below
    # is kept comfortably under that so benign UEs never trip the
    # threshold on their own, only the injected attack does.
    return [
        # Distinct normal_dst_ip per UE -- MultidomainCorrelator groups
        # by dst_ip, so benign UEs sharing one placeholder destination
        # would have their otherwise-individually-safe pps summed
        # together and could cross the threshold as a false "multi-
        # source flood toward the same target", which isn't what's
        # being simulated here.
        UE(imsi=1, ip="10.60.0.2", baseline_mbps=0.3, jitter_mbps=0.15, normal_dst_ip="203.0.113.10"),
        UE(imsi=2, ip="10.60.0.3", baseline_mbps=0.4, jitter_mbps=0.15, normal_dst_ip="203.0.113.20"),
        # Stops on its own at attack_end_tick -- lets check_mobile_unblocks
        # (orchestration/controller.py) observe a real drop in this UE's
        # reported throughput and react with an explicit "unblock" RC
        # command, the same way a real attacker going quiet would.
        UE(imsi=3, ip="10.60.0.4", baseline_mbps=0.3, jitter_mbps=0.1, normal_dst_ip="203.0.113.30",
           attack_window=(10, attack_end_tick), attack_mbps=45.0),
    ]


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tick", type=float, default=2.0, help="seconds between samples")
    parser.add_argument("--duration", type=float, default=0.0, help="total seconds to run, 0 = forever")
    parser.add_argument("--out-csv", default=DEFAULT_CSV_PATH)
    parser.add_argument("--ue-ip-map", default=str(DEFAULT_UE_IP_MAP_PATH))
    parser.add_argument("--no-attack", action="store_true", help="disable the injected UE 3 flood")
    parser.add_argument("--attack-end-tick", type=int, default=25,
                         help="tick at which UE 3's flood stops on its own")
    parser.add_argument("--rc-command-queue", default=str(DEFAULT_RC_COMMAND_QUEUE_PATH),
                         help="JSONL queue MobileNetworkAdapter.apply_mitigation() writes to")
    args = parser.parse_args()

    ues = default_ues(attack_end_tick=args.attack_end_tick)
    ues_by_imsi = {ue.imsi: ue for ue in ues}
    if args.no_attack:
        for ue in ues:
            ue.attack_window = None

    write_ue_ip_map(ues, Path(args.ue_ip_map))
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
        attack_desc = f"flood from tick {ue.attack_window[0]}" if ue.attack_window else "benign only"
        print(f"  IMSI {ue.imsi} -> {ue.ip} ({attack_desc})")

    print(f"[ul_traffic_simulator] appending to {args.out_csv} every {args.tick}s "
          f"({'forever' if args.duration <= 0 else f'{args.duration}s total'}) -- Ctrl+C to stop")

    tick = 0
    start = time.time()
    rc_command_offset = 0
    try:
        with open(args.out_csv, "a", newline="") as f:
            writer = csv.writer(f)
            while args.duration <= 0 or (time.time() - start) < args.duration:
                commands, rc_command_offset = read_new_commands(
                    args.rc_command_queue, rc_command_offset
                )
                for command in commands:
                    imsi = command.get("imsi")
                    ue = ues_by_imsi.get(imsi)
                    if ue is None:
                        continue
                    # Not printed -- the controller already reports both
                    # block and unblock through its own MITIGACION
                    # dashboard/logger line (ryu_controller_2.py's
                    # _run_pipeline); this process only needs to apply the
                    # effect to its synthetic UEs, the same way a real RAN
                    # wouldn't echo a RIC CONTROL REQUEST back as a log.
                    action = command.get("action")
                    if action == "unblock":
                        # Lifts the quarantine immediately rather than
                        # extending it -- an "unblock" with a leftover
                        # duration field would otherwise be treated like
                        # another throttle command below.
                        ue.throttled_until = None
                        continue
                    duration = command.get("duration", 60)
                    ue.apply_throttle(duration)

                for ue in ues:
                    row = ue.sample(tick)
                    writer.writerow([row[c] for c in
                                      ["timestamp", "imsi", "gnb_id", "dst_ip", "ul_thr_mbps",
                                       "prb_usage_pct", "sinr_db", "state"]])
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
                time.sleep(args.tick)
    except KeyboardInterrupt:
        print("\n[ul_traffic_simulator] stopped")


if __name__ == "__main__":
    sys.exit(main())
