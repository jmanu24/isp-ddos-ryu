#!/usr/bin/env python3
"""
ue_kpm_monitor.py — O-RAN multidomain DDoS proposal.

Companion to simulation/ue_traffic_generator.py: measures the REAL
traffic that script's hping3 processes put on the wire and converts it
into the same KPM CSV format telemetry/mobile_adapter.py already tails
(_CSV_COLUMNS_EXT below, kept byte-for-byte identical to that module's
own column order) -- so MobileNetworkAdapter needs zero changes.

Meant to run ON r1 (see ring_topology.py) -- every UE's traffic is
cross-subnet by construction (see ue_traffic_generator.py's SCENARIOS),
so r1 is the one point in the topology that necessarily sees all of it.

Measurement is counter-based, not per-packet sniffing: one nftables
counter per (UE, L4 protocol), installed at the prerouting hook, polled
and diffed over time -- the same counter-delta pattern
collectors/flow_collector.py already uses for OpenFlow flow-stats, and
for the same reason: per-packet userspace processing would drop packets
(or fall behind) under real hping3 --flood-level pps, while a kernel-side
counter never can.

prb_usage_pct/sinr_db have no real equivalent in this setup -- there is
no actual radio layer between a Mininet host and r1 -- so they remain
fundamentally synthetic no matter what. They're derived here from the
REAL measured ul_thr_mbps via the same per-protocol radio-degradation
profile ul_traffic_simulator.py used for its formula-generated rate, so
at least they stay internally consistent with real load instead of being
a second, independently-invented number.

Usage: launched automatically by ue_traffic_generator.py on r1, or run
standalone once that generator (or any producer of the same nftables
counters) is up:
  python3 simulation/ue_kpm_monitor.py
"""

import argparse
import csv
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))
import config.settings as settings  # noqa: E402
from oran_bridge.ue_ip_map import load_ue_ip_map  # noqa: E402 -- no ryu dependency, safe to import directly

# Must match telemetry/mobile_adapter.py's DEFAULT_KPM_CSV_PATH -- kept as
# a duplicated constant rather than importing that module, same
# ryu-dependency-avoidance convention ul_traffic_simulator.py already uses.
DEFAULT_CSV_PATH = "/tmp/ddos_xapp_events.csv"
DEFAULT_UE_IP_MAP_PATH = REPO_DIR / "config" / "ue_ip_map.csv"
DEFAULT_UE_STATE_PATH = "/tmp/ue_traffic_state.json"

# Must match telemetry/mobile_adapter.py's _CSV_COLUMNS_EXT exactly --
# this is the contract MobileNetworkAdapter.collect() reads positionally
# (no header row; see _append_csv_rows below).
_CSV_COLUMNS_EXT = ["timestamp", "imsi", "gnb_id", "dst_ip", "ul_thr_mbps",
                     "prb_usage_pct", "sinr_db", "state", "dst_port", "protocol"]

_NFT_TABLE = "ue_acct"
_NFT_PROTOS = ("tcp", "udp", "icmp")
_COUNTER_NAME_RE = re.compile(r"^ue_(\d+)_(tcp|udp|icmp)$")

# Same per-protocol radio-degradation profile ul_traffic_simulator.py's
# UE._ATTACK_RADIO_PROFILES used, applied here to a REAL measured
# ul_thr_mbps instead of a formula-generated one. sat_mbps was calibrated
# against that formula's deterministic attack rates -- real hping3
# --flood throughput is hardware-dependent and likely needs empirical
# recalibration once measured on the actual test VM.
_ATTACK_RADIO_PROFILES = {
    "UDP":     dict(sat_mbps=45.0, prb_floor=85.0, prb_ceiling=100.0, sinr_floor=2.0,  sinr_ceiling=6.0),
    "TCP_SYN": dict(sat_mbps=1.0,  prb_floor=15.0, prb_ceiling=30.0,  sinr_floor=10.0, sinr_ceiling=18.0),
    "ICMP":    dict(sat_mbps=3.0,  prb_floor=20.0, prb_ceiling=40.0,  sinr_floor=8.0,  sinr_ceiling=15.0),
}


def _run(argv: list, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, check=check)


def _reset_file(path) -> None:
    """
    Removes `path` if it exists, rather than opening it for in-place
    truncation -- see ue_traffic_generator.py's _reset_file for why:
    on an NFS-mounted /tmp with root_squash, overwriting a PRE-EXISTING
    file owned by a different (non-squashed) user gets EACCES/EPERM even
    though this process's own EUID is 0, while creating a brand-new file
    only needs write access to the parent directory. Duplicated rather
    than imported, same no-cross-import convention this file's other
    constants already follow.
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


# ---------------------------------------------------------------------------
# nftables setup -- rebuilt from scratch whenever ue_ip_map.csv changes.
# ---------------------------------------------------------------------------

def _ensure_nft_setup(ue_ip_map: Dict[int, str]) -> None:
    """
    Deletes and recreates the whole table on every call rather than
    reconciling against what's already there. An earlier attempt at
    incremental add-if-missing (checking only whether a same-named
    counter object already existed) left a real run stuck: a prior
    invocation that hit the "ip protocol" rule-syntax bug (see below)
    still created the COUNTER objects successfully before failing on the
    RULE that references them, so on the next run -- even after fixing
    the syntax -- every counter "already existed" and rule creation was
    skipped entirely, leaving 15 orphaned, permanently-zero counters
    with nothing ever incrementing them. A full delete+rebuild can't
    end up in that half-wired state.
    """
    _run(["nft", "delete", "table", "inet", _NFT_TABLE])
    _run(["nft", "add", "table", "inet", _NFT_TABLE])
    _run(["nft", "add", "chain", "inet", _NFT_TABLE, "pre",
          "{ type filter hook prerouting priority -150; }"])

    for imsi, ip in ue_ip_map.items():
        for proto in _NFT_PROTOS:
            name = f"ue_{imsi}_{proto}"
            _run(["nft", "add", "counter", "inet", _NFT_TABLE, name])
            # "ip protocol <proto>" matches the IP protocol field --
            # a bare "tcp"/"udp"/"icmp" keyword instead starts a payload
            # expression (nft then expects a field like sport/dport to
            # follow it, not "counter"), which is NOT the same thing and
            # fails with "unexpected counter, expecting length or
            # checksum or sport or dport" (confirmed against a real run).
            result = _run(["nft", "add", "rule", "inet", _NFT_TABLE, "pre",
                           "ip", "saddr", ip, "ip", "protocol", proto, "counter", "name", name])
            if result.returncode != 0:
                print(f"[MOBILE-MON] WARNING: no se pudo instalar el contador nft "
                      f"para imsi={imsi} proto={proto}: {result.stderr.strip()}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Measurement -- counter-delta pattern, same shape as
# collectors/flow_collector.py's flow-stats rate computation.
# ---------------------------------------------------------------------------

@dataclass
class _Sample:
    time: float
    tcp_bytes: int = 0
    tcp_pkts: int = 0
    udp_bytes: int = 0
    udp_pkts: int = 0
    icmp_bytes: int = 0
    icmp_pkts: int = 0


def _poll_counters(known_imsis) -> Dict[int, _Sample]:
    now = time.time()
    samples: Dict[int, _Sample] = {imsi: _Sample(time=now) for imsi in known_imsis}

    result = _run(["nft", "-j", "list", "counters", "table", "inet", _NFT_TABLE])
    if result.returncode != 0:
        return samples
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return samples

    for item in data.get("nftables", []):
        counter = item.get("counter")
        if not counter:
            continue
        match = _COUNTER_NAME_RE.match(counter.get("name", ""))
        if not match:
            continue
        imsi, proto = int(match.group(1)), match.group(2)
        sample = samples.setdefault(imsi, _Sample(time=now))
        setattr(sample, f"{proto}_bytes", counter.get("bytes", 0))
        setattr(sample, f"{proto}_pkts", counter.get("packets", 0))

    return samples


def _prb_sinr(protocol: str, low_slow: bool, ul_thr_mbps: float):
    if low_slow or protocol not in _ATTACK_RADIO_PROFILES:
        # Flat, low-impact profile -- matches ul_traffic_simulator.py's
        # own idle/low_slow formula (a trickle that never saturates the
        # channel by design).
        prb = min(100.0, max(0.0, 5.0 + ul_thr_mbps * 3.0))
        sinr = random.uniform(15.0, 25.0)
        return prb, sinr

    profile = _ATTACK_RADIO_PROFILES[protocol]
    saturation = min(ul_thr_mbps / profile["sat_mbps"], 1.0) if profile["sat_mbps"] > 0 else 1.0
    prb = profile["prb_floor"] + (profile["prb_ceiling"] - profile["prb_floor"]) * saturation
    prb = min(100.0, max(0.0, prb + random.uniform(-2.0, 2.0)))
    sinr = profile["sinr_ceiling"] - (profile["sinr_ceiling"] - profile["sinr_floor"]) * saturation
    sinr = max(0.1, sinr + random.uniform(-1.0, 1.0))
    return prb, sinr


def _rate_row(imsi: int, meta: dict, prev: _Sample, cur: _Sample) -> Optional[dict]:
    dt = cur.time - prev.time
    if dt < settings.MIN_FLOW_RATE_DT:
        return None

    deltas = {
        "TCP": (cur.tcp_bytes - prev.tcp_bytes, cur.tcp_pkts - prev.tcp_pkts),
        "UDP": (cur.udp_bytes - prev.udp_bytes, cur.udp_pkts - prev.udp_pkts),
        "ICMP": (cur.icmp_bytes - prev.icmp_bytes, cur.icmp_pkts - prev.icmp_pkts),
    }
    # Counters are monotonic cumulative -- a negative delta means nft was
    # reloaded/reset between polls. Skip rather than report a bogus
    # negative rate, same defensive check
    # OrchestrationController.record_block_traffic applies to its own
    # drop-rule counters.
    if any(b < 0 or p < 0 for b, p in deltas.values()):
        return None

    total_bytes = sum(b for b, _ in deltas.values())
    total_pkts = sum(p for _, p in deltas.values())

    declared_protocol = meta.get("protocol", "UDP")
    if total_pkts == 0:
        protocol = declared_protocol
    else:
        dominant = max(deltas, key=lambda k: deltas[k][1])
        # TCP alone can't distinguish a real SYN_FLOOD from LOW_SLOW's
        # trickle purely from packet content -- both are bare SYNs (see
        # module docstring). UDP/ICMP are unambiguous straight off the
        # wire, so only those override the declared tag.
        protocol = declared_protocol if dominant == "TCP" else dominant

    ul_thr_mbps = (total_bytes * 8) / dt / 1e6
    pps = total_pkts / dt

    prb, sinr = _prb_sinr(protocol, meta.get("low_slow", False), ul_thr_mbps)

    return {
        "timestamp": f"{cur.time:.6f}",
        "imsi": str(imsi),
        "gnb_id": meta.get("gnb_id", ""),
        "dst_ip": meta.get("dst_ip") or "*",
        "ul_thr_mbps": f"{ul_thr_mbps:.6f}",
        "prb_usage_pct": f"{prb:.3f}",
        "sinr_db": f"{sinr:.3f}",
        "state": "ACTIVE" if pps > 0.01 else "IDLE",
        "dst_port": str(meta.get("dst_port", 0)),
        "protocol": protocol,
    }


# ---------------------------------------------------------------------------
# CSV output -- no header row, matching MobileNetworkAdapter.collect()'s
# positional zip() against _CSV_COLUMNS_EXT.
# ---------------------------------------------------------------------------

def _append_csv_rows(csv_path: str, rows: list) -> None:
    with open(csv_path, "a", newline="") as f:
        writer = csv.writer(f)
        for row in rows:
            writer.writerow([row[c] for c in _CSV_COLUMNS_EXT])


# ---------------------------------------------------------------------------
# mtime-watched reload helpers -- same pattern
# MobileNetworkAdapter._refresh_ue_ip_map already uses.
# ---------------------------------------------------------------------------

def _load_ue_state(path: str) -> Dict[int, dict]:
    try:
        with open(path) as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return {int(imsi): meta for imsi, meta in raw.items()}


def _maybe_reload(path, prev_mtime, loader):
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None, prev_mtime, False
    if mtime == prev_mtime:
        return None, prev_mtime, False
    return loader(path), mtime, True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv-path", default=DEFAULT_CSV_PATH)
    parser.add_argument("--ue-ip-map", default=str(DEFAULT_UE_IP_MAP_PATH))
    parser.add_argument("--ue-state-path", default=DEFAULT_UE_STATE_PATH)
    parser.add_argument("--tick", type=float, default=settings.COLLECT_INTERVAL)
    args = parser.parse_args()

    if not shutil.which("nft"):
        print("ERROR: 'nft' no esta instalado -- no se puede medir trafico real.", file=sys.stderr)
        sys.exit(1)

    # Fresh CSV for this run -- same truncate-on-startup convention
    # ul_traffic_simulator.py's main() already uses.
    _reset_file(args.csv_path)
    Path(args.csv_path).touch()

    ue_ip_map: Dict[int, str] = {}
    ue_ip_map_mtime = None
    ue_state: Dict[int, dict] = {}
    ue_state_mtime = None
    prev_samples: Dict[int, _Sample] = {}

    print(f"*** ue_kpm_monitor.py: escribiendo {args.csv_path}, tick={args.tick}s")

    while True:
        new_map, new_mtime, changed = _maybe_reload(args.ue_ip_map, ue_ip_map_mtime, load_ue_ip_map)
        if changed:
            ue_ip_map, ue_ip_map_mtime = new_map, new_mtime
            print(f"[MOBILE-MON] UE_MAP_RELOADED path={args.ue_ip_map} entries={len(ue_ip_map)}")
            if ue_ip_map:
                _ensure_nft_setup(ue_ip_map)

        new_state, new_state_mtime, changed = _maybe_reload(args.ue_state_path, ue_state_mtime, _load_ue_state)
        if changed:
            ue_state, ue_state_mtime = new_state, new_state_mtime

        samples = _poll_counters(ue_ip_map.keys())
        rows = []
        for imsi, cur in samples.items():
            prev = prev_samples.get(imsi)
            meta = ue_state.get(imsi)
            if prev is not None and meta is not None:
                row = _rate_row(imsi, meta, prev, cur)
                if row:
                    rows.append(row)
            prev_samples[imsi] = cur

        if rows:
            _append_csv_rows(args.csv_path, rows)

        time.sleep(args.tick)


if __name__ == "__main__":
    main()
