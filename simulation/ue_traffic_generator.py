#!/usr/bin/env python3
"""
ue_traffic_generator.py — O-RAN multidomain DDoS proposal.

Real-traffic replacement for simulation/ul_traffic_simulator.py's mobile
UE telemetry source. That script invents ul_thr_mbps/prb_usage_pct/
sinr_db numbers from formulas and writes them straight to a CSV -- no
packet is ever actually sent. This script instead builds
topologies/ring_topology.py's Mininet ring and drives real hping3
subprocesses from its real hosts, one per simulated UE, each with its
own spoofed source IP from the 10.60.0.x UE address space, independent
of which physical host (h1-h4) actually runs it -- forwarding/
learning_switch.py's L3 rule matches ipv4_src/ipv4_dst straight off the
packet's own IP header with no reverse-path check, so this is exactly
the same spoofed-source model DDOS_DISTRIBUTED already assumes
elsewhere in this project.

This script's ONLY job is to make the traffic exist and to react to
mitigation by actually killing the offending UE's process. Measuring
that traffic and turning it into the KPM CSV telemetry/mobile_adapter.py
tails is simulation/ue_kpm_monitor.py's job -- launched by this script on
r1, since every UE's traffic is cross-subnet and must transit it.

Usage (root, Linux, with Mininet + hping3 + nft installed):
  sudo python3 simulation/ue_traffic_generator.py --scenario udp_flood
  sudo python3 simulation/ue_traffic_generator.py --scenario distributed_syn --duration 90
  sudo python3 simulation/ue_traffic_generator.py --scenario low_slow --duration 120
  sudo python3 simulation/ue_traffic_generator.py --interactive

See deploy/run_mobile_scenario.sh for the full controller+topology+
generator+monitor pipeline in one command.
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))
import config.settings as settings  # noqa: E402
from topologies.ring_topology import LinuxRouter, wait_for_rstp_convergence  # noqa: E402

from mininet.net import Mininet  # noqa: E402
from mininet.node import RemoteController, OVSSwitch  # noqa: E402
from mininet.link import TCLink  # noqa: E402
from mininet.cli import CLI  # noqa: E402

# Must match telemetry/mobile_adapter.py's DEFAULT_KPM_CSV_PATH /
# DEFAULT_RC_COMMAND_QUEUE_PATH -- duplicated, not imported, so this
# standalone process never pulls in telemetry/__init__.py's ryu
# dependency chain (same convention ul_traffic_simulator.py already
# uses for the same reason).
DEFAULT_CSV_PATH = "/tmp/ddos_xapp_events.csv"
DEFAULT_RC_COMMAND_QUEUE_PATH = "/tmp/oran_rc_commands.jsonl"
DEFAULT_UE_IP_MAP_PATH = REPO_DIR / "config" / "ue_ip_map.csv"
# New sidecar this real-traffic split needs: static per-UE metadata
# (dst_ip/protocol/dst_port/gnb_id/low_slow) that ue_kpm_monitor.py can't
# derive from raw packets alone -- see _write_ue_state's docstring.
DEFAULT_UE_STATE_PATH = "/tmp/ue_traffic_state.json"

_TEST_MCC, _TEST_MNC = "001", "01"
_GNB_ID = f"{_TEST_MCC}{_TEST_MNC}-1"


@dataclass
class UeSpec:
    imsi: int
    ip: str
    physical_host: str
    gnb_id: str
    target_ip: str
    protocol: str  # "UDP" | "TCP_SYN" | "ICMP" | "TCP" (low_slow)
    dst_port: int = 0
    low_slow: bool = False
    benign: bool = False
    # hping3 rate flags -- ["--flood"] for a volumetric single attacker,
    # ["-i", "u<micros>"] for a rate-capped multi-source UE (see SCENARIOS'
    # per-scenario comments for the pps math behind each choice).
    rate_flags: List[str] = field(default_factory=lambda: ["--flood"])
    # Fixed benign-loop target, NEVER mutated by _start_attack/_stop_attack
    # (interactive mode) -- deliberately kept separate from target_ip
    # (which _start_attack DOES overwrite to the attack's destination).
    # orchestration/controller.py's check_mobile_unblocks() releases a
    # block only once this exact (src_ip, dst_ip) pair stops producing
    # ANY telemetry -- it doesn't check protocol (see that method's own
    # comment on why: neither adapter can report more than one protocol
    # per source per cycle anyway). If the post-throttle benign loop kept
    # sending toward the SAME dst_ip the attack used, it would look
    # exactly like "the attacker is still there, just quiet" forever --
    # confirmed on a real run: the block only ever cleared when the whole
    # monitor process died with the script, never during normal
    # operation. A benign_target_ip outside the ring's real host space
    # (10.0.x.10, the only sensible attack targets) can never collide
    # with whatever destination an attack just used.
    benign_target_ip: str = ""


# ---------------------------------------------------------------------------
# Scenarios -- same 5 names/semantics as ul_traffic_simulator.py's SCENARIOS,
# now expressed as real hosts/IPs/hping3 rates instead of formula parameters.
# ---------------------------------------------------------------------------

def _benign_ues() -> List[UeSpec]:
    # Distinct target per benign UE so their traffic doesn't collapse into
    # one dst_ip bucket at the correlation layer (see
    # ul_traffic_simulator.py's own _benign_ues comment for the same
    # reasoning). hping3 has no lognormal/bursty mode, so these run an
    # ICMP on/off shell loop instead (see _benign_loop_argv) -- a cruder
    # approximation of the old formula's bursty traffic, not equivalent
    # fidelity.
    #
    # Targets a placeholder outside the ring (203.0.113.0/24, TEST-NET-3)
    # rather than a real h1-h4 host -- deliberately NEVER the same address
    # space a scenario's attacker targets (always a real 10.0.x.10 ring
    # host), so a benign UE's own background traffic can never collide
    # with check_mobile_unblocks()'s per-(src_ip,dst_ip) presence check
    # for an unrelated attacker (see UeSpec.benign_target_ip). r1's nft
    # prerouting hook still counts it regardless of whether the packet is
    # ultimately routable past r1.
    return [
        UeSpec(imsi=1, ip="10.60.0.2", physical_host="h1", gnb_id=_GNB_ID,
               target_ip="203.0.113.10", protocol="ICMP", benign=True,
               benign_target_ip="203.0.113.10"),
        UeSpec(imsi=2, ip="10.60.0.3", physical_host="h2", gnb_id=_GNB_ID,
               target_ip="203.0.113.20", protocol="ICMP", benign=True,
               benign_target_ip="203.0.113.20"),
    ]


def scenario_udp_flood() -> List[UeSpec]:
    ues = _benign_ues()
    ues.append(UeSpec(
        imsi=3, ip="10.60.0.4", physical_host="h3", gnb_id=_GNB_ID,
        target_ip="10.0.2.10", protocol="UDP", dst_port=0,
        rate_flags=["--flood"],
    ))
    return ues


def scenario_syn_flood() -> List[UeSpec]:
    ues = _benign_ues()
    ues.append(UeSpec(
        imsi=3, ip="10.60.0.4", physical_host="h3", gnb_id=_GNB_ID,
        target_ip="10.0.2.10", protocol="TCP_SYN", dst_port=443,
        rate_flags=["--flood"],
    ))
    return ues


def scenario_icmp_flood() -> List[UeSpec]:
    ues = _benign_ues()
    ues.append(UeSpec(
        imsi=3, ip="10.60.0.4", physical_host="h3", gnb_id=_GNB_ID,
        target_ip="10.0.2.10", protocol="ICMP", dst_port=0,
        rate_flags=["--flood"],
    ))
    return ues


def scenario_distributed_syn() -> List[UeSpec]:
    """
    5 UEs (>= settings.DIST_MIN_SOURCES) at ~100 pps each (-i u10000 =
    10ms interval) toward the SAME target -- 500 pps aggregate, clear of
    DIST_PPS_THRESHOLD=300, with near-equal per-source rate so entropy
    clears DIST_ENTROPY_THRESHOLD=0.7. Spread across 3 of the 4 physical
    ring hosts (never the target's own host) so every source's traffic
    is guaranteed to cross r1, where ue_kpm_monitor.py measures it.
    """
    ues = _benign_ues()
    hosts = ["h1", "h3", "h4", "h1", "h3"]
    for i in range(5):
        ues.append(UeSpec(
            imsi=10 + i, ip=f"10.60.0.{20 + i}", physical_host=hosts[i], gnb_id=_GNB_ID,
            target_ip="10.0.2.10", protocol="TCP_SYN", dst_port=443,
            rate_flags=["-i", "u10000"],
        ))
    return ues


def scenario_low_slow() -> List[UeSpec]:
    """
    settings.LOW_SLOW_MOBILE_MIN_SOURCES UEs, each a steady ~2 pps
    (-i u500000 = 500ms interval) of bare SYNs -- comfortably under
    LOW_SLOW_MOBILE_MAX_PPS=8.0 per source, individually indistinguishable
    from light traffic; only their combined persistence over
    LOW_SLOW_MOBILE_MIN_CYCLES flags it. hping3 never completes a real
    handshake, so "connection stays open" is approximated by a low,
    constant-source-port (--keep) SYN rate, not a real persistent TCP
    connection.
    """
    ues = _benign_ues()
    hosts = ["h1", "h2", "h3", "h1", "h2"]
    n = settings.LOW_SLOW_MOBILE_MIN_SOURCES
    for i in range(n):
        ues.append(UeSpec(
            imsi=20 + i, ip=f"10.60.0.{30 + i}", physical_host=hosts[i % len(hosts)], gnb_id=_GNB_ID,
            target_ip="10.0.4.10", protocol="TCP", dst_port=80, low_slow=True,
            rate_flags=["-i", "u500000"],
        ))
    return ues


SCENARIOS = {
    "udp_flood": scenario_udp_flood,
    "syn_flood": scenario_syn_flood,
    "icmp_flood": scenario_icmp_flood,
    "distributed_syn": scenario_distributed_syn,
    "low_slow": scenario_low_slow,
}


# ---------------------------------------------------------------------------
# hping3 command construction
# ---------------------------------------------------------------------------

def _hping3_argv(ue: UeSpec) -> List[str]:
    argv = ["hping3", "-a", ue.ip]
    if ue.protocol == "UDP":
        argv += ["--udp", "-p", str(ue.dst_port), "--keep"]
    elif ue.protocol in ("TCP_SYN", "TCP"):
        argv += ["-S", "-p", str(ue.dst_port), "--keep"]
    elif ue.protocol == "ICMP":
        argv += ["--icmp"]
    argv += ue.rate_flags
    argv.append(ue.target_ip)
    return argv


# On/off ICMP burst loop standing in for hping3's lack of a bursty/
# lognormal mode -- real bursts (3-7 packets at ~5 pps) separated by
# 4-11s idle gaps, launched once per benign UE and left running for the
# whole scenario.
_BENIGN_LOOP_TEMPLATE = (
    "while true; do "
    "hping3 -a {ip} --icmp -c $((RANDOM % 5 + 3)) -i u200000 {target} >/dev/null 2>&1; "
    "sleep $((RANDOM % 8 + 4)); "
    "done"
)


def _benign_loop_argv(ue: UeSpec) -> List[str]:
    # ue.benign_target_ip, NEVER ue.target_ip -- the latter gets
    # overwritten to the attack's destination by _start_attack and is
    # meaningless for what the benign loop should be sending toward. See
    # UeSpec.benign_target_ip's docstring.
    return ["bash", "-c", _BENIGN_LOOP_TEMPLATE.format(ip=ue.ip, target=ue.benign_target_ip)]


# ---------------------------------------------------------------------------
# Topology (duplicates topologies/ring_topology.py's topology() body
# rather than editing that file, so it stays the canonical single-purpose
# OpenFlow-domain demo topology; only LinuxRouter/wait_for_rstp_convergence
# are actually reused from it).
# ---------------------------------------------------------------------------

def _disable_rp_filter(r1) -> None:
    """
    UEs live on 10.60.0.0/24, a subnet r1 has no real route for. Linux's
    reverse-path filter would otherwise silently drop every spoofed UE
    packet as martian -- the whole real-traffic scheme would then produce
    zero observable traffic with no error anywhere to explain why. Must
    run before any hping3 process starts.
    """
    r1.cmd('sysctl -w net.ipv4.conf.all.rp_filter=0')
    r1.cmd('sysctl -w net.ipv4.conf.default.rp_filter=0')
    for i in range(4):
        r1.cmd(f'sysctl -w net.ipv4.conf.r1-eth{i}.rp_filter=0')
    print("*** rp_filter deshabilitado en r1 -- el trafico spoofed de 10.60.0.0/24 ahora se reenviara")


def build_topology():
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink)

    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    switches = [net.addSwitch(f's{i}', protocols='OpenFlow13') for i in range(1, 5)]
    r1 = net.addHost('r1', cls=LinuxRouter)
    hosts = [
        net.addHost(f'h{i}', ip=f'10.0.{i}.10/24', defaultRoute=f'via 10.0.{i}.1')
        for i in range(1, 5)
    ]

    for h, s in zip(hosts, switches):
        net.addLink(h, s)
    for s in switches:
        net.addLink(r1, s)
    for a, b in zip(switches, switches[1:] + switches[:1]):
        net.addLink(a, b)

    net.start()

    for s in switches:
        s.cmd(f'ovs-vsctl set Bridge {s.name} rstp_enable=true')
    for i in range(1, 5):
        r1.cmd(f'ip addr add 10.0.{i}.1/24 dev r1-eth{i - 1}')

    wait_for_rstp_convergence(switches)
    _disable_rp_filter(r1)

    return net, r1, hosts


# ---------------------------------------------------------------------------
# Shared state written for ue_kpm_monitor.py
# ---------------------------------------------------------------------------

def _reset_file(path) -> None:
    """
    Ensures `path` starts this run as a fresh, absent file -- removed
    rather than opened for in-place truncation. Matters when /tmp is a
    network mount with root squashed to an unprivileged uid server-side:
    the local os.geteuid()==0 check passes, but the actual write/rename
    syscall against a PRE-EXISTING file owned by a different (non-
    squashed) user gets EACCES/EPERM from the server, since the squashed
    identity is neither that file's owner nor real root as far as the
    server is concerned. Removing it first and letting the caller create
    a brand-new one only needs write access to the parent directory
    (world-writable for /tmp's default 1777 mode), which root-squash
    still grants -- only *overwriting a file you don't own* is blocked.
    """
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise SystemExit(
            f"ERROR: no se pudo preparar {path} ({exc}).\n"
            f"Si /tmp esta montado por NFS con root_squash, borra el archivo "
            f"viejo como tu usuario normal (sin sudo) antes de reintentar:\n"
            f"  rm -f {path}"
        )


def _write_ue_ip_map(ues: List[UeSpec], path: Path) -> None:
    _reset_file(path)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["imsi", "ip"])
        for ue in ues:
            writer.writerow([ue.imsi, ue.ip])


def _write_ue_state(ues: List[UeSpec], path: str) -> None:
    """
    Static per-UE metadata ue_kpm_monitor.py can't measure from raw
    counters alone (dst_ip/protocol/dst_port/gnb_id/low_slow) -- the same
    category of "generator knows what it's simulating, real KPM never
    could" info ul_traffic_simulator.py already baked into its CSV rows
    directly. Written once at startup and never rewritten: each UE's
    identity (which target it talks to, what protocol) is fixed for the
    life of one scenario run. Whether traffic is actually flowing right
    now is for the monitor's own nftables counters to determine, not this
    file -- so there's nothing to update later.
    """
    state = {
        str(ue.imsi): {
            "dst_ip": ue.target_ip,
            "protocol": ue.protocol,
            "dst_port": ue.dst_port,
            "gnb_id": ue.gnb_id,
            "low_slow": ue.low_slow,
        }
        for ue in ues
    }
    tmp = f"{path}.tmp"
    _reset_file(tmp)
    with open(tmp, "w") as f:
        json.dump(state, f)
    _reset_file(path)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# RC mitigation command queue -- same offset-tracking pattern
# telemetry/mobile_adapter.py's CSV tailing and ul_traffic_simulator.py's
# own read_new_commands() already use.
# ---------------------------------------------------------------------------

def _read_new_commands(path: str, offset: int) -> tuple:
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


@dataclass
class _RuntimeState:
    procs: Dict[int, object] = field(default_factory=dict)
    throttled_until: Dict[int, float] = field(default_factory=dict)
    rc_offset: int = 0


def _terminate(proc) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _consume_rc_commands(ues_by_imsi: Dict[int, UeSpec], state: _RuntimeState, rc_path: str) -> None:
    """
    Applies throttle/unblock commands off the RC queue for real: unlike
    ul_traffic_simulator.py (which just reported a near-zero rate while
    "throttled"), this actually kills the matching UE's hping3 process --
    ue_kpm_monitor.py's counters will then measure real silence, not a
    faked number.
    """
    commands, state.rc_offset = _read_new_commands(rc_path, state.rc_offset)
    for command in commands:
        imsi = command.get("imsi")
        ue = ues_by_imsi.get(imsi)
        if ue is None:
            continue
        if command.get("action") == "unblock":
            state.throttled_until.pop(imsi, None)
            continue
        duration = command.get("duration", 60)
        state.throttled_until[imsi] = time.time() + duration
        _terminate(state.procs.pop(imsi, None))
        print(f"[MOBILE-GEN] Throttled imsi={imsi} ip={ue.ip} for {duration}s (hping3 process killed)")


# ---------------------------------------------------------------------------
# Reconciliation loop -- starts/stops each UE's real process to match its
# attack window and current throttle state.
# ---------------------------------------------------------------------------

def _reconcile_ue(ue: UeSpec, host, state: _RuntimeState, elapsed: float,
                   attack_start_s: float, attack_end_s: float) -> None:
    now = time.time()
    until = state.throttled_until.get(ue.imsi)
    throttled = until is not None and until > now
    if until is not None and not throttled:
        state.throttled_until.pop(ue.imsi, None)

    should_run = ue.benign or (attack_start_s <= elapsed < attack_end_s)
    should_run = should_run and not throttled

    proc = state.procs.get(ue.imsi)
    running = proc is not None and proc.poll() is None

    if should_run and not running:
        argv = _benign_loop_argv(ue) if ue.benign else _hping3_argv(ue)
        state.procs[ue.imsi] = host.popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        label = "benign loop" if ue.benign else f"attack ({ue.protocol})"
        print(f"[MOBILE-GEN] imsi={ue.imsi} ip={ue.ip} host={ue.physical_host} -> "
              f"{ue.target_ip} START [{label}]")
    elif not should_run and running:
        _terminate(proc)
        state.procs[ue.imsi] = None
        print(f"[MOBILE-GEN] imsi={ue.imsi} ip={ue.ip} STOP")


def _tick_loop(ues: List[UeSpec], ues_by_imsi: Dict[int, UeSpec], host_map: dict,
               state: _RuntimeState, args, attack_end_s: float, stop_event: threading.Event) -> None:
    start = time.time()
    while not stop_event.is_set():
        elapsed = time.time() - start
        if args.duration and elapsed >= args.duration:
            stop_event.set()
            break

        _consume_rc_commands(ues_by_imsi, state, args.rc_command_queue)
        for ue in ues:
            _reconcile_ue(ue, host_map[ue.physical_host], state, elapsed, args.attack_start_s, attack_end_s)

        time.sleep(args.tick)


# ---------------------------------------------------------------------------
# Interactive mode -- menu-driven, mirrors ul_traffic_simulator.py's
# --interactive (same _print_async/_prompt* pattern so a background
# thread's status lines never garble whatever the user is mid-typing)
# and bng_interactive.py's real-process start/stop semantics (a UE
# "attacking" is a live hping3 process, not just an in-memory flag --
# "elegir otro ataque" tears down the previous UE(s)' process and starts
# a fresh one, same as bng_interactive.py's "cambiar").
# ---------------------------------------------------------------------------

_CURRENT_PROMPT = {"text": None}


def _print_async(message: str) -> None:
    prompt_text = _CURRENT_PROMPT["text"]
    if prompt_text:
        print()
        print(message)
        print(prompt_text, end="", flush=True)
    else:
        print(message)


def _prompt(prompt: str, default: str = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    text = f"{prompt}{suffix}: "
    _CURRENT_PROMPT["text"] = text
    try:
        raw = input(text).strip()
    finally:
        _CURRENT_PROMPT["text"] = None
    return raw if raw else (default or "")


def _prompt_int(prompt: str, default: int, min_value: int = None) -> int:
    while True:
        raw = _prompt(prompt, str(default))
        try:
            value = int(raw)
        except ValueError:
            print("  Ingresa un numero entero valido.")
            continue
        if min_value is not None and value < min_value:
            print(f"  Debe ser >= {min_value}.")
            continue
        return value


_ATTACK_TYPES = {
    "1": ("UDP Flood", "single"),
    "2": ("TCP SYN Flood", "single"),
    "3": ("ICMP Flood", "single"),
    "4": ("Distributed TCP SYN Flood", "distributed"),
    "5": ("Low and Slow", "low_slow"),
}

# One ring host per pool UE, round-robin. Benign traffic targets a
# placeholder OUTSIDE the ring (never one of h1-h4's real 10.0.x.10
# addresses, which is what an interactive attack would realistically
# target) -- see UeSpec.benign_target_ip for why that separation matters
# for check_mobile_unblocks()'s presence-based unblock signal. r1's nft
# prerouting hook still counts it regardless of onward routability.
_POOL_HOSTS = ["h1", "h2", "h3", "h4"]


def _build_interactive_pool(n: int) -> List[UeSpec]:
    pool = []
    for i in range(n):
        host = _POOL_HOSTS[i % len(_POOL_HOSTS)]
        benign_target = f"203.0.113.{10 + i}"
        pool.append(UeSpec(
            imsi=i + 1, ip=f"10.60.0.{2 + i}", physical_host=host, gnb_id=_GNB_ID,
            target_ip=benign_target, protocol="ICMP", benign=True,
            benign_target_ip=benign_target,
        ))
    return pool


def _print_pool_menu(pool: List[UeSpec]) -> None:
    attacking = sum(1 for u in pool if not u.benign)
    print()
    print("=== Simulador interactivo de trafico movil (hping3 real) ===")
    print(f"UEs configuradas: {len(pool)} ({attacking} atacando actualmente)")
    print("Elige un tipo de ataque:")
    print("  1) UDP Flood")
    print("  2) TCP SYN Flood")
    print("  3) ICMP Flood")
    print("  4) Distributed TCP SYN Flood (varias UE como origen)")
    print("  5) Low and Slow")
    print("  0) Salir")


def _free_ues(pool: List[UeSpec]) -> List[UeSpec]:
    """UEs currently running their benign loop -- available to repurpose
    as an attacker. Mirrors ul_traffic_simulator.py's _free_ues (there,
    "free" means attack_window is None; here it means ue.benign is still
    True, i.e. no attack hping3 process has replaced its benign loop)."""
    return [ue for ue in pool if ue.benign]


def _choose_single_attacker(pool: List[UeSpec]) -> "UeSpec | None":
    free = _free_ues(pool)
    if not free:
        print("  No hay ninguna UE libre (todas atacando ya). Detén un ataque primero.")
        return None
    print("  UEs disponibles: " + ", ".join(f"IMSI {u.imsi} ({u.ip}, host {u.physical_host})" for u in free))
    while True:
        raw = _prompt("  Que UE ataca? (IMSI)", str(free[0].imsi))
        matches = [u for u in free if str(u.imsi) == raw]
        if matches:
            return matches[0]
        print("  Esa UE no existe o ya esta ocupada -- elige una de la lista.")


def _choose_group(pool: List[UeSpec], min_sources: int, default_count: int) -> "List[UeSpec] | None":
    free = _free_ues(pool)
    if len(free) < min_sources:
        print(f"  Solo hay {len(free)} UE(s) libres y este ataque necesita al menos "
              f"{min_sources} para que el detector lo clasifique como tal. "
              f"Detén otro ataque o configura mas UEs al iniciar.")
        if not free:
            return None
    count = _prompt_int(
        f"  Cuantas UEs participan? (minimo recomendado {min_sources}, libres: {len(free)})",
        default=min(default_count, len(free)) if free else default_count,
    )
    if count > len(free):
        print(f"  Solo hay {len(free)} libres -- se usaran todas.")
        count = len(free)
    if count < min_sources:
        print(f"  Aviso: con {count} UE(s) es posible que el detector NO lo clasifique "
              f"como este tipo de ataque (minimo recomendado: {min_sources}).")
    return free[:count]


def _prompt_rate_flags(default) -> List[str]:
    raw = _prompt("  Tasa (pps por UE, o 'flood' para maxima velocidad)", str(default))
    if raw.strip().lower() in ("flood", "f"):
        return ["--flood"]
    try:
        pps = max(1.0, float(raw))
    except ValueError:
        return ["--flood"]
    return ["-i", f"u{max(1, round(1e6 / pps))}"]


def _start_attack(ue: UeSpec, host, state: _RuntimeState, protocol: str, dst_port: int,
                   target_ip: str, low_slow: bool, rate_flags: List[str],
                   pool: List[UeSpec], ue_state_path: str) -> None:
    _terminate(state.procs.pop(ue.imsi, None))  # stop its benign loop
    ue.protocol, ue.dst_port, ue.target_ip = protocol, dst_port, target_ip
    ue.low_slow, ue.rate_flags, ue.benign = low_slow, rate_flags, False
    state.procs[ue.imsi] = host.popen(_hping3_argv(ue), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # ue_kpm_monitor.py's dst_ip/protocol/dst_port tag for this IMSI comes
    # entirely from this file (real KPM has no L4 visibility, see that
    # module's docstring) -- without refreshing it here, the monitor would
    # keep reporting whatever this UE's PREVIOUS role was (its initial
    # benign target, on the very first attack) instead of what it's
    # actually sending now, breaking detection for any target other than
    # whatever happened to be in ue_state.json already.
    _write_ue_state(pool, ue_state_path)


def _stop_attack(ue: UeSpec, host, state: _RuntimeState, pool: List[UeSpec], ue_state_path: str) -> None:
    _terminate(state.procs.pop(ue.imsi, None))
    ue.benign = True
    state.procs[ue.imsi] = host.popen(_benign_loop_argv(ue), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Refresh ue_state.json's dst_ip back to this UE's benign target too --
    # _write_ue_state always reads ue.target_ip (see its docstring), which
    # _start_attack left pointed at the just-stopped attack's destination.
    ue.target_ip = ue.benign_target_ip
    _write_ue_state(pool, ue_state_path)


def _configure_attack(pool: List[UeSpec], host_map: dict, state: _RuntimeState,
                       lock: threading.Lock, ue_state_path: str) -> "tuple | None":
    while True:
        _print_pool_menu(pool)
        choice = _prompt("Opcion", "0")
        if choice == "0":
            return None
        if choice not in _ATTACK_TYPES:
            print("  Opcion no valida.")
            continue
        name, kind = _ATTACK_TYPES[choice]
        break

    target_ip = _prompt("  IP objetivo del ataque", "10.0.2.10")

    if kind == "single":
        ue = _choose_single_attacker(pool)
        if ue is None:
            return None
        if choice == "1":  # UDP Flood
            protocol, dst_port = "UDP", 0
        elif choice == "2":  # TCP SYN Flood
            dst_port = _prompt_int("  Puerto TCP objetivo", 443)
            protocol = "TCP_SYN"
        else:  # ICMP Flood
            protocol, dst_port = "ICMP", 0
        rate_flags = _prompt_rate_flags("flood")
        with lock:
            _start_attack(ue, host_map[ue.physical_host], state, protocol, dst_port, target_ip, False, rate_flags,
                           pool, ue_state_path)
        return f"{name} desde IMSI {ue.imsi} ({ue.ip}) -> {target_ip}:{dst_port}", [ue]

    if kind == "distributed":
        group = _choose_group(pool, settings.DIST_MIN_SOURCES, default_count=5)
        if not group:
            return None
        dst_port = _prompt_int("  Puerto TCP objetivo", 443)
        rate_flags = _prompt_rate_flags(100)  # ~pps/source clearing SYN_THRESHOLD with margin
        with lock:
            for ue in group:
                _start_attack(ue, host_map[ue.physical_host], state, "TCP_SYN", dst_port, target_ip, False,
                               rate_flags, pool, ue_state_path)
        imsis = ", ".join(str(u.imsi) for u in group)
        return f"{name} desde {len(group)} UE(s) (IMSI {imsis}) -> {target_ip}:{dst_port}", group

    # low_slow
    group = _choose_group(pool, settings.LOW_SLOW_MOBILE_MIN_SOURCES,
                           default_count=settings.LOW_SLOW_MOBILE_MIN_SOURCES)
    if not group:
        return None
    dst_port = _prompt_int("  Puerto TCP objetivo", 80)
    rate_flags = _prompt_rate_flags(2)  # stays comfortably under LOW_SLOW_MOBILE_MAX_PPS=8.0
    with lock:
        for ue in group:
            _start_attack(ue, host_map[ue.physical_host], state, "TCP", dst_port, target_ip, True,
                           rate_flags, pool, ue_state_path)
    imsis = ", ".join(str(u.imsi) for u in group)
    return f"{name} desde {len(group)} UE(s) (IMSI {imsis}) -> {target_ip}:{dst_port}", group


def _apply_mitigation(ue: UeSpec, host, state: _RuntimeState, pool: List[UeSpec], ue_state_path: str) -> None:
    """
    Reacts to a real block/rate_limit command for an attacking UE by
    immediately reverting it to its benign loop -- unlike the headless
    generator (whose _reconcile_ue also has an attack window/duration to
    respect), here the user is driving attacks manually, so "mitigated"
    simply means "back to normal now"; there's nothing else scheduling
    this UE to attack again. The controller's own check_mobile_unblocks()/
    UNBLOCK_CONFIRM_CYCLES still drive the REAL unblock timing on its
    side, based on this UE's telemetry toward the ORIGINAL attack dst_ip
    genuinely stopping -- which requires _stop_attack's ue_state.json
    refresh below to actually happen, or the block would look like it's
    still "present" against the stale attack dst_ip forever.
    """
    _stop_attack(ue, host, state, pool, ue_state_path)


def _rc_watch_loop(pool_by_imsi: Dict[int, UeSpec], host_map: dict, state: _RuntimeState,
                    rc_path: str, tick: float, lock: threading.Lock, stop_event: threading.Event,
                    pool: List[UeSpec], ue_state_path: str) -> None:
    offset = 0
    while not stop_event.is_set():
        commands, offset = _read_new_commands(rc_path, offset)
        for command in commands:
            if command.get("action") == "unblock":
                continue  # already reverted to benign immediately on block, see _apply_mitigation
            ue = pool_by_imsi.get(command.get("imsi"))
            if ue is None or ue.benign:
                continue
            with lock:
                _apply_mitigation(ue, host_map[ue.physical_host], state, pool, ue_state_path)
            _print_async(f"[MOBILE-INT] Mitigado: IMSI {ue.imsi} ({ue.ip}) bloqueado por el "
                         f"controlador -> vuelve a trafico normal")
        stop_event.wait(tick)


def run_interactive(args) -> None:
    print("=== Simulador interactivo del dominio Mobile (hping3 real) ===")
    n = _prompt_int("Cuantas UEs quieres simular?", default=3, min_value=2)
    pool = _build_interactive_pool(n)
    pool_by_imsi = {ue.imsi: ue for ue in pool}

    _reset_file(args.rc_command_queue)
    Path(args.rc_command_queue).touch()
    # ryu-manager (telemetry/mobile_adapter.py's apply_mitigation, which
    # appends to this same path) normally runs as a regular user, not
    # root -- this generator does (Mininet/hping3 need raw sockets). A
    # file this process creates defaults to root-owned, other=read-only,
    # so the controller's own append would fail with EACCES the first
    # time it tries to report a mitigation (confirmed against a real
    # run). World-writable is fine here: it's an ephemeral /tmp queue
    # for one local demo run, not a security boundary.
    os.chmod(args.rc_command_queue, 0o666)
    _write_ue_ip_map(pool, Path(args.ue_ip_map))
    _write_ue_state(pool, args.ue_state_path)

    print(f"*** {n} UE(s) configuradas:")
    for ue in pool:
        print(f"  IMSI {ue.imsi} -> {ue.ip} (host {ue.physical_host}, gNB {ue.gnb_id})")

    net, r1, hosts = build_topology()
    host_map = {h.name: h for h in hosts}
    state = _RuntimeState()
    lock = threading.Lock()
    stop_event = threading.Event()
    monitor_proc = None

    try:
        if not args.no_monitor:
            monitor_argv = [
                "python3", str(REPO_DIR / "simulation" / "ue_kpm_monitor.py"),
                "--csv-path", args.csv_path,
                "--ue-ip-map", args.ue_ip_map,
                "--ue-state-path", args.ue_state_path,
                "--tick", str(settings.COLLECT_INTERVAL),
            ]
            monitor_proc = r1.popen(monitor_argv)
            print("*** ue_kpm_monitor.py corriendo en r1")

        with lock:
            for ue in pool:
                state.procs[ue.imsi] = host_map[ue.physical_host].popen(
                    _benign_loop_argv(ue), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("*** Trafico benigno de fondo iniciado para todas las UEs")

        rc_thread = threading.Thread(
            target=_rc_watch_loop,
            args=(pool_by_imsi, host_map, state, args.rc_command_queue, args.tick, lock, stop_event,
                  pool, args.ue_state_path),
            daemon=True,
        )
        rc_thread.start()

        while True:
            result = _configure_attack(pool, host_map, state, lock, args.ue_state_path)
            if result is None:
                break
            description, attacking_ues = result
            print(f"\n*** Ataque iniciado: {description}")
            print("Escribe 'stop' y Enter para detenerlo y elegir otro ataque.")
            while True:
                _CURRENT_PROMPT["text"] = "> "
                try:
                    cmd = input("> ").strip().lower()
                finally:
                    _CURRENT_PROMPT["text"] = None
                if cmd == "":
                    continue
                if cmd in ("stop", "s"):
                    with lock:
                        for ue in attacking_ues:
                            if not ue.benign:  # a controller mitigation may have already stopped it
                                _stop_attack(ue, host_map[ue.physical_host], state, pool, args.ue_state_path)
                    print("*** Ataque detenido. Las UEs volvieron a trafico normal.")
                    break
                print("  Comando no reconocido -- escribe 'stop' para detener el ataque actual.")
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        print("*** Cerrando...")
        stop_event.set()
        for proc in state.procs.values():
            _terminate(proc)
        _terminate(monitor_proc)
        net.stop()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--interactive", action="store_true",
                         help="menu-driven mode: choose/stop attacks on demand instead of a fixed scenario")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="udp_flood")
    parser.add_argument("--duration", type=float, default=0.0,
                         help="total seconds to run; 0 = forever, drops into the Mininet CLI (Ctrl-D to stop)")
    parser.add_argument("--attack-start-s", type=float, default=10.0)
    parser.add_argument("--attack-end-s", type=float, default=None,
                         help="default: duration-5 seconds, or never if --duration 0")
    parser.add_argument("--tick", type=float, default=1.0, help="reconcile/RC-queue poll interval, seconds")
    parser.add_argument("--csv-path", default=DEFAULT_CSV_PATH)
    parser.add_argument("--rc-command-queue", default=DEFAULT_RC_COMMAND_QUEUE_PATH)
    parser.add_argument("--ue-ip-map", default=str(DEFAULT_UE_IP_MAP_PATH))
    parser.add_argument("--ue-state-path", default=DEFAULT_UE_STATE_PATH)
    parser.add_argument("--no-monitor", action="store_true",
                         help="don't auto-launch ue_kpm_monitor.py on r1 (run it yourself)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: corre esto como root -- Mininet/hping3 necesitan sockets raw.", file=sys.stderr)
        sys.exit(1)

    if args.interactive:
        run_interactive(args)
        return

    attack_end_s = args.attack_end_s
    if attack_end_s is None:
        attack_end_s = (args.duration - 5) if args.duration > 0 else float("inf")

    ues = SCENARIOS[args.scenario]()
    ues_by_imsi = {ue.imsi: ue for ue in ues}
    n_attackers = sum(1 for u in ues if not u.benign)

    # Discard stale commands from a previous run so a fresh scenario
    # never starts pre-throttled by leftover mitigation state.
    _reset_file(args.rc_command_queue)
    Path(args.rc_command_queue).touch()
    # ryu-manager (telemetry/mobile_adapter.py's apply_mitigation, which
    # appends to this same path) normally runs as a regular user, not
    # root -- this generator does (Mininet/hping3 need raw sockets). A
    # file this process creates defaults to root-owned, other=read-only,
    # so the controller's own append would fail with EACCES the first
    # time it tries to report a mitigation (confirmed against a real
    # run). World-writable is fine here: it's an ephemeral /tmp queue
    # for one local demo run, not a security boundary.
    os.chmod(args.rc_command_queue, 0o666)
    _write_ue_ip_map(ues, Path(args.ue_ip_map))
    _write_ue_state(ues, args.ue_state_path)

    print(f"*** Escenario mobile '{args.scenario}': {len(ues)} UE(s), {n_attackers} atacante(s)")

    net, r1, hosts = build_topology()
    host_map = {h.name: h for h in hosts}
    state = _RuntimeState()
    stop_event = threading.Event()
    monitor_proc = None

    try:
        if not args.no_monitor:
            monitor_argv = [
                "python3", str(REPO_DIR / "simulation" / "ue_kpm_monitor.py"),
                "--csv-path", args.csv_path,
                "--ue-ip-map", args.ue_ip_map,
                "--ue-state-path", args.ue_state_path,
                "--tick", str(settings.COLLECT_INTERVAL),
            ]
            monitor_proc = r1.popen(monitor_argv)
            print("*** ue_kpm_monitor.py corriendo en r1")

        ticker = threading.Thread(
            target=_tick_loop,
            args=(ues, ues_by_imsi, host_map, state, args, attack_end_s, stop_event),
            daemon=True,
        )
        ticker.start()

        if args.duration:
            ticker.join()
        else:
            CLI(net)
            stop_event.set()
            ticker.join(timeout=5)

    finally:
        print("*** Deteniendo procesos hping3/monitor y la topologia...")
        for proc in state.procs.values():
            _terminate(proc)
        _terminate(monitor_proc)
        net.stop()


if __name__ == "__main__":
    main()
