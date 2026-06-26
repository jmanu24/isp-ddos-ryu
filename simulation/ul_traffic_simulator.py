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

import argparse
import csv
import json
import math
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
_CSV_COLUMNS = ["timestamp", "imsi", "gnb_id", "dst_ip", "ul_thr_mbps",
                "prb_usage_pct", "sinr_db", "state", "dst_port", "protocol"]


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
    low_slow                   : while attacking, models a Slowloris-style
                                 UE -- connection stays open and active
                                 but deliberately trickles data, so it
                                 does NOT saturate radio resources or
                                 degrade the channel the way a real flood
                                 does (see sample()'s attack branch).
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
        protocol: str = "UDP",
        dst_port: int = 0,
        low_slow: bool = False,
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
        self.protocol = protocol
        self.dst_port = dst_port
        self.low_slow = low_slow

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
            if self.low_slow:
                # Slowloris-style: the connection stays open and active,
                # but deliberately trickles data -- a single one of these
                # looks just like ordinary light traffic; what's anomalous
                # is many of them at once toward the same target (see
                # DDoSDetectionEngine.analyze_low_slow_mobile).
                prb_usage_pct = min(100.0, max(0.0, 5.0 + ul_thr_mbps * 3.0))
                sinr_db = random.uniform(15.0, 25.0)
            else:
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
            "dst_port": str(self.dst_port),
            "protocol": self.protocol,
        }


# config/settings.py thresholds each scenario is tuned against (so the
# attack magnitude is always comfortably past the threshold that
# classifies it, with margin -- not just barely over):
#   SYN_THRESHOLD=10 pps  -> ~0.041 Mbps  (TCP_SYN)
#   UDP_THRESHOLD=200 pps -> ~0.82 Mbps   (UDP)
#   ICMP_THRESHOLD=150pps -> ~0.61 Mbps   (ICMP)
#   DIST_MIN_SOURCES=5, DIST_ENTROPY_THRESHOLD=0.7 (near-equal per-source rate)
#   LOW_SLOW_MOBILE_MAX_PPS=8.0 -> ~0.033 Mbps ceiling, MIN_SOURCES=5
# via MobileNetworkAdapter's pps = bps / ASSUMED_AVG_PACKET_SIZE_BYTES(512).

_BENIGN_UES = [
    dict(imsi=1, ip="10.60.0.2", baseline_mbps=0.3, jitter_mbps=0.15, normal_dst_ip="203.0.113.10"),
    dict(imsi=2, ip="10.60.0.3", baseline_mbps=0.4, jitter_mbps=0.15, normal_dst_ip="203.0.113.20"),
]


def _benign_ues():
    # Distinct normal_dst_ip per UE -- MultidomainCorrelator groups by
    # dst_ip, so benign UEs sharing one placeholder destination would
    # have their otherwise-individually-safe pps summed together and
    # could cross a threshold as a false multi-source flood, which isn't
    # what's being simulated here.
    return [UE(**kwargs) for kwargs in _BENIGN_UES]


def scenario_udp_flood(attack_end_tick: int):
    """Single UE, UDP volumetric flood -- the original/default scenario."""
    ues = _benign_ues()
    ues.append(UE(
        imsi=3, ip="10.60.0.4", baseline_mbps=0.3, jitter_mbps=0.1, normal_dst_ip="203.0.113.30",
        attack_window=(10, attack_end_tick), attack_mbps=45.0, protocol="UDP",
    ))
    return ues


def scenario_syn_flood(attack_end_tick: int):
    """Single UE, TCP SYN flood toward a typical web port."""
    ues = _benign_ues()
    ues.append(UE(
        imsi=3, ip="10.60.0.4", baseline_mbps=0.3, jitter_mbps=0.1, normal_dst_ip="203.0.113.30",
        attack_window=(10, attack_end_tick), attack_mbps=3.0,
        protocol="TCP_SYN", dst_port=443,
    ))
    return ues


def scenario_icmp_flood(attack_end_tick: int):
    """Single UE, ICMP flood."""
    ues = _benign_ues()
    ues.append(UE(
        imsi=3, ip="10.60.0.4", baseline_mbps=0.3, jitter_mbps=0.1, normal_dst_ip="203.0.113.30",
        attack_window=(10, attack_end_tick), attack_mbps=5.0,
        protocol="ICMP", dst_port=0,
    ))
    return ues


def scenario_distributed_syn(attack_end_tick: int):
    """
    Five UEs (>= settings.DIST_MIN_SOURCES), each contributing a near-
    equal TCP_SYN rate toward the same target -- the near-uniform
    per-source distribution (high entropy) is what makes
    DDoSDetectionEngine classify this as DDOS_DISTRIBUTED instead of
    five independent SYN_FLOOD attackers.
    """
    ues = _benign_ues()
    for i in range(5):
        ues.append(UE(
            imsi=10 + i, ip=f"10.60.0.{20 + i}",
            baseline_mbps=0.3, jitter_mbps=0.1, normal_dst_ip=f"203.0.113.{40 + i}",
            attack_window=(10, attack_end_tick), attack_mbps=2.0,
            protocol="TCP_SYN", dst_port=443,
        ))
    return ues


def scenario_low_slow(attack_end_tick: int):
    """
    settings.LOW_SLOW_MOBILE_MIN_SOURCES UEs, each holding a low, sub-
    threshold, deliberately steady rate (well under
    LOW_SLOW_MOBILE_MAX_PPS) toward the same target for many consecutive
    cycles -- any one of them alone looks like ordinary light traffic;
    it's the persistence of several at once that
    analyze_low_slow_mobile() flags (its score formula gives this exact
    minimum count enough headroom to actually clear DECISION_THRESHOLD
    once confirmed, not just get detected and never mitigated). Low
    jitter on purpose: a real Slowloris-style connection trickles a
    steady drip, not a noisy one.
    """
    ues = _benign_ues()
    for i in range(settings.LOW_SLOW_MOBILE_MIN_SOURCES):
        ues.append(UE(
            imsi=20 + i, ip=f"10.60.0.{30 + i}",
            baseline_mbps=0.3, jitter_mbps=0.1, normal_dst_ip=f"203.0.113.{50 + i}",
            attack_window=(10, attack_end_tick), attack_mbps=0.02,
            # Plain "TCP" (not "TCP_SYN") -- a real Slowloris connection is
            # fully established, not a bare SYN, and "TCP" isn't one of
            # _PROTOCOL_CHECKS' literal tags, so this never competes with
            # the volumetric SYN_FLOOD path even by coincidence.
            protocol="TCP", dst_port=80, low_slow=True,
        ))
    return ues


SCENARIOS = {
    "udp_flood": scenario_udp_flood,
    "syn_flood": scenario_syn_flood,
    "icmp_flood": scenario_icmp_flood,
    "distributed_syn": scenario_distributed_syn,
    "low_slow": scenario_low_slow,
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
):
    """
    The actual sampling loop: every tick_seconds, consume pending RC
    commands, sample every UE, and append one row per UE to out_csv.
    Shared by the scripted (--scenario) entry point and the interactive
    mode's background thread -- stop_event lets the interactive mode
    end this from another thread without relying on KeyboardInterrupt
    (which only the main thread receives).
    """
    ues_by_imsi = {ue.imsi: ue for ue in ues}
    tick = 0
    start = time.time()
    rc_command_offset = 0

    with open(out_csv, "a", newline="") as f:
        writer = csv.writer(f)
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            if duration > 0 and (time.time() - start) >= duration:
                return

            rc_command_offset = _consume_rc_commands(ues_by_imsi, rc_command_queue, rc_command_offset)

            for ue in ues:
                row = ue.sample(tick)
                writer.writerow([row[c] for c in _CSV_COLUMNS])
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
    parser.add_argument("--rc-command-queue", default=str(DEFAULT_RC_COMMAND_QUEUE_PATH),
                         help="JSONL queue MobileNetworkAdapter.apply_mitigation() writes to")
    args = parser.parse_args()

    if args.interactive:
        return run_interactive(args)

    ues = SCENARIOS[args.scenario](args.attack_end_tick)
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
            f"{ue.protocol} flood from tick {ue.attack_window[0]}" if ue.attack_window and not ue.low_slow
            else f"low-and-slow ({ue.protocol}) from tick {ue.attack_window[0]}" if ue.attack_window
            else "benign only"
        )
        print(f"  IMSI {ue.imsi} -> {ue.ip} ({attack_desc})")

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

def _prompt(prompt: str, default: "str | None" = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    raw = input(f"{prompt}{suffix}: ").strip()
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


def build_normal_ues(n: int) -> list:
    """N UEs with ordinary, individually-benign background traffic --
    each gets its own normal_dst_ip (see SCENARIOS' "Distinct
    normal_dst_ip" comment for why that matters to the correlator)."""
    ues = []
    for i in range(n):
        ues.append(UE(
            imsi=i + 1,
            ip=f"10.60.0.{2 + i}",
            baseline_mbps=round(random.uniform(0.2, 0.5), 2),
            jitter_mbps=0.15,
            normal_dst_ip=f"203.0.113.{10 + i}",
        ))
    return ues


_ATTACK_TYPES = {
    "1": ("UDP Flood", "single"),
    "2": ("TCP SYN Flood", "single"),
    "3": ("ICMP Flood", "single"),
    "4": ("Distributed TCP SYN Flood", "distributed"),
    "5": ("Low and Slow", "low_slow"),
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
    print("  5) Low and Slow")
    print("  0) Salir")


def _free_ues(ues: list) -> list:
    """UEs not currently part of a running attack -- available to pick from."""
    return [ue for ue in ues if not ue.attack_window]


def _choose_single_attacker(ues: list) -> "UE | None":
    free = _free_ues(ues)
    if not free:
        print("  No hay ninguna UE libre (todas están atacando ya). Detén un ataque primero.")
        return None
    print("  UEs disponibles: " + ", ".join(f"IMSI {u.imsi}" for u in free))
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


def _configure_attack(ues: list) -> "tuple[str, list] | None":
    """Prompts for an attack type and its parameters, applies it to the
    chosen UE(s), and returns (description, affected_ues) -- or None if
    the user cancelled / no UE was available."""
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
            ue.protocol, ue.dst_port, ue.low_slow = "UDP", 0, False
        elif choice == "2":  # TCP SYN Flood
            mbps = _prompt_float(
                f"  Throughput de ataque en Mbps (umbral SYN_THRESHOLD={settings.SYN_THRESHOLD}pps)",
                3.0,
            )
            dst_port = _prompt_int("  Puerto TCP objetivo", 443)
            ue.protocol, ue.dst_port, ue.low_slow = "TCP_SYN", dst_port, False
        else:  # ICMP Flood
            mbps = _prompt_float(
                f"  Throughput de ataque en Mbps (umbral ICMP_THRESHOLD={settings.ICMP_THRESHOLD}pps)",
                5.0,
            )
            ue.protocol, ue.dst_port, ue.low_slow = "ICMP", 0, False
        ue.attack_mbps = mbps
        ue.attack_target_ip = target_ip
        ue.attack_window = (0, 10 ** 9)  # "until stopped" -- see is_attacking()
        return f"{name} desde IMSI {ue.imsi} -> {target_ip} ({mbps} Mbps)", [ue]

    if kind == "distributed":
        group = _choose_group(ues, settings.DIST_MIN_SOURCES, default_count=5)
        if not group:
            return None
        mbps = _prompt_float("  Throughput de ataque por UE en Mbps", 2.0)
        dst_port = _prompt_int("  Puerto TCP objetivo", 443)
        for ue in group:
            ue.protocol, ue.dst_port, ue.low_slow = "TCP_SYN", dst_port, False
            ue.attack_mbps = mbps
            ue.attack_target_ip = target_ip
            ue.attack_window = (0, 10 ** 9)
        imsis = ", ".join(str(u.imsi) for u in group)
        return f"{name} desde {len(group)} UE(s) (IMSI {imsis}) -> {target_ip} ({mbps} Mbps c/u)", group

    # low_slow
    group = _choose_group(ues, settings.LOW_SLOW_MOBILE_MIN_SOURCES,
                           default_count=settings.LOW_SLOW_MOBILE_MIN_SOURCES)
    if not group:
        return None
    max_mbps = settings.LOW_SLOW_MOBILE_MAX_PPS * 512 * 8 / 1e6
    mbps = _prompt_float(
        f"  Throughput de ataque por UE en Mbps (techo recomendado ~{max_mbps:.3f})",
        round(max_mbps * 0.6, 4),
    )
    dst_port = _prompt_int("  Puerto TCP objetivo", 80)
    for ue in group:
        ue.protocol, ue.dst_port, ue.low_slow = "TCP", dst_port, True
        ue.attack_mbps = mbps
        ue.attack_target_ip = target_ip
        ue.attack_window = (0, 10 ** 9)
    imsis = ", ".join(str(u.imsi) for u in group)
    return f"{name} desde {len(group)} UE(s) (IMSI {imsis}) -> {target_ip} ({mbps} Mbps c/u)", group


def run_interactive(args):
    print("=== Simulador interactivo de tráfico móvil ===")
    n = _prompt_int("¿Cuántas UEs quieres simular con tráfico normal?", default=3, min_value=1)
    ues = build_normal_ues(n)

    write_ue_ip_map(ues, Path(args.ue_ip_map))
    Path(args.out_csv).write_text("")
    Path(args.rc_command_queue).write_text("")
    print(f"[ul_traffic_simulator] {n} UE(s) configuradas, tráfico normal:")
    for ue in ues:
        print(f"  IMSI {ue.imsi} -> {ue.ip} (baseline {ue.baseline_mbps} Mbps -> {ue.normal_dst_ip})")

    stop_event = threading.Event()
    thread = threading.Thread(
        target=_run_tick_loop,
        args=(ues, args.out_csv, args.rc_command_queue, args.tick),
        kwargs={"verbose": False, "stop_event": stop_event},
        daemon=True,
    )
    thread.start()
    print(f"[ul_traffic_simulator] generando telemetría cada {args.tick}s en segundo plano "
          f"({args.out_csv})")

    try:
        while True:
            result = _configure_attack(ues)
            if result is None:
                break
            description, attacking_ues = result
            print(f"\n[ul_traffic_simulator] Ataque iniciado: {description}")
            print("Escribe 'stop' y Enter para detenerlo y elegir otro ataque.")
            while True:
                cmd = input("> ").strip().lower()
                if cmd in ("stop", "s", ""):
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
