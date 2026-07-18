#!/usr/bin/env python3
"""
analysis/parse_timing_stats.py

Extrae estadísticas de tiempos del log del controlador (ryu-manager):

  Tm  — Tiempo de mitigación: desde primera DETECTION hasta primera
         BLOCK/THROTTLE para el mismo (domain, dst_ip).

  Tu  — Tiempo de bloqueo activo: desde primera BLOCK/THROTTLE hasta
         UNBLOCK/UNTHROTTLE para la misma (src_ip, domain).

Uso:
  python3 analysis/parse_timing_stats.py /path/to/ryu-manager.log
  python3 analysis/parse_timing_stats.py /path/to/ryu-manager.log --csv out.csv --scenario 5d

El log debe ser la salida de ryu-manager con el formato:
  YYYY-MM-DD HH:MM:SS LEVEL FlowStatsIDS [domain] EVENT_TYPE: ...
"""

import argparse
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional


_TS_FMT = "%Y-%m-%d %H:%M:%S"

_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s+\S+"
    r"\s+\S+"
    r"\s+\[(?P<domain>[^\]]+)\]"
    r"\s+(?P<event_type>\w+):"
    r"\s+(?P<message>.+)$"
)

_DETECTION_RE = re.compile(
    r"ATTACK_DETECTED\s+(?P<attack_type>\S+)"
    r"\s+source=(?P<src>\S+)"
    r"\s+destination=(?P<dst>[^:]+):(?P<port>\d+)/(?P<proto>\S+)"
)

# Matches all four action keywords in one pass.
_ACTION_RE = re.compile(
    r"^(?P<action>BLOCK|THROTTLE|UNBLOCK|UNTHROTTLE)\s+(?P<attack_type>\S+)"
)
# Optional fields that may follow:
_SRC_IP_RE   = re.compile(r"src_ip=(\S+)")
_SOURCE_RE   = re.compile(r"source=(\S+)")
_DST_RE      = re.compile(r"destination=([^:]+):(\d+)/(\S+)")


def _ts(s: str) -> datetime:
    return datetime.strptime(s, _TS_FMT)


def _parse_action_msg(msg: str) -> Optional[dict]:
    """Parse a MITIGATION log message. Returns None if not a recognized action."""
    am = _ACTION_RE.match(msg)
    if not am:
        return None
    action      = am.group("action")
    attack_type = am.group("attack_type")

    src = None
    m = _SRC_IP_RE.search(msg)
    if m:
        src = m.group(1)
    if src is None:
        m = _SOURCE_RE.search(msg)
        if m:
            src = m.group(1)

    dst, dst_port, proto = None, None, None
    m = _DST_RE.search(msg)
    if m:
        dst, dst_port, proto = m.group(1), int(m.group(2)), m.group(3)

    return {
        "action": action,
        "attack_type": attack_type,
        "src": src or "*",
        "dst": dst,
        "dst_port": dst_port,
        "proto": proto,
    }


def parse_log(path: str):
    detections  = []  # {ts, domain, attack_type, src, dst, dst_port, proto}
    mitigations = []  # {ts, domain, action, attack_type, src, dst}
    unblocks    = []  # same

    with open(path, "r") as f:
        for line in f:
            m = _LINE_RE.match(line.strip())
            if not m:
                continue
            ts      = _ts(m.group("ts"))
            domain  = m.group("domain")
            ev_type = m.group("event_type")
            msg     = m.group("message")

            if ev_type == "DETECTION":
                dm = _DETECTION_RE.search(msg)
                if dm:
                    detections.append({
                        "ts": ts, "domain": domain,
                        "attack_type": dm.group("attack_type"),
                        "src": dm.group("src"),
                        "dst": dm.group("dst"),
                        "dst_port": int(dm.group("port")),
                        "proto": dm.group("proto"),
                    })

            elif ev_type == "MITIGATION":
                parsed = _parse_action_msg(msg)
                if not parsed:
                    continue
                entry = {"ts": ts, "domain": domain, **parsed}
                if parsed["action"] in ("BLOCK", "THROTTLE"):
                    mitigations.append(entry)
                else:
                    unblocks.append(entry)

    return detections, mitigations, unblocks


def _infer_dst(mit: dict, detections: list) -> Optional[str]:
    """
    For mobile THROTTLE entries that have no `dst` in the log line, infer
    dst from the nearest preceding DETECTION for the same domain.
    """
    if mit["dst"]:
        return mit["dst"]
    # Find the most recent detection for this domain before (or at) the mitigation time.
    candidates = [
        d for d in detections
        if d["domain"] == mit["domain"] and d["ts"] <= mit["ts"]
    ]
    if candidates:
        return candidates[-1]["dst"]
    return None


def compute_stats(detections, mitigations, unblocks):
    """
    Returns one record per BLOCK/THROTTLE event with Tm and Tu.
    """
    records = []

    for mit in mitigations:
        dst    = _infer_dst(mit, detections)
        src    = mit["src"]
        domain = mit["domain"]
        mit_ts = mit["ts"]

        # Tm: nearest DETECTION for same (domain, dst) within 60s before mitigation.
        det_match = None
        for det in detections:
            if det["domain"] != domain:
                continue
            if dst and det["dst"] != dst:
                continue
            dt = (mit_ts - det["ts"]).total_seconds()
            if 0.0 <= dt <= 60.0:
                det_match = det
                break   # detections are in order; first match is earliest

        Tm = round((mit_ts - det_match["ts"]).total_seconds(), 3) if det_match else None

        # Tu: nearest UNBLOCK/UNTHROTTLE for same (src, domain) after mitigation.
        unblock_match = None
        for ub in unblocks:
            if ub["domain"] != domain:
                continue
            if ub["src"] != src:
                continue
            if ub["ts"] >= mit_ts:
                unblock_match = ub
                break

        Tu = round((unblock_match["ts"] - mit_ts).total_seconds(), 3) if unblock_match else None

        records.append({
            "domain":        domain,
            "attack_type":   mit["attack_type"],
            "src":           src,
            "dst":           dst or "",
            "detection_at":  det_match["ts"].strftime(_TS_FMT) if det_match else "",
            "mitigation_at": mit_ts.strftime(_TS_FMT),
            "unblock_at":    unblock_match["ts"].strftime(_TS_FMT) if unblock_match else "",
            "Tm_s":          Tm if Tm is not None else "",
            "Tu_s":          Tu if Tu is not None else "",
        })

    return records


def summarize(records):
    by_domain: Dict[str, list] = defaultdict(list)
    for r in records:
        by_domain[r["domain"]].append(r)

    print(f"\n{'='*70}")
    print(f"{'RESUMEN DE TIEMPOS':^70}")
    print(f"{'='*70}")

    for domain, recs in sorted(by_domain.items()):
        tms = [r["Tm_s"] for r in recs if r["Tm_s"] != ""]
        tus = [r["Tu_s"] for r in recs if r["Tu_s"] != ""]
        n   = len(recs)
        print(f"\n  Dominio: {domain.upper()}  ({n} bloques)")
        if tms:
            print(f"    Tm (detección → mitigación):   "
                  f"media={sum(tms)/len(tms):.3f}s  "
                  f"min={min(tms):.3f}s  max={max(tms):.3f}s  n={len(tms)}")
        else:
            print(f"    Tm: sin datos de detección previos en ventana 60s")
        if tus:
            print(f"    Tu (mitigación → desbloqueo):  "
                  f"media={sum(tus)/len(tus):.1f}s  "
                  f"min={min(tus):.1f}s  max={max(tus):.1f}s  n={len(tus)}")
        else:
            print(f"    Tu: sin desbloqueos registrados")

    all_tms = [r["Tm_s"] for r in records if r["Tm_s"] != ""]
    all_tus = [r["Tu_s"] for r in records if r["Tu_s"] != ""]
    print(f"\n  TOTAL  ({len(records)} bloques)")
    if all_tms:
        print(f"    Tm: media={sum(all_tms)/len(all_tms):.3f}s  "
              f"min={min(all_tms):.3f}s  max={max(all_tms):.3f}s")
    if all_tus:
        print(f"    Tu: media={sum(all_tus)/len(all_tus):.1f}s  "
              f"min={min(all_tus):.1f}s  max={max(all_tus):.1f}s")
    print()


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("log", help="Ruta al log de ryu-manager")
    ap.add_argument("--csv", metavar="FILE", help="Exportar CSV detallado")
    ap.add_argument("--scenario", metavar="LABEL",
                    help="Etiqueta de escenario para el CSV (ej. '5d')")
    args = ap.parse_args()

    detections, mitigations, unblocks = parse_log(args.log)
    print(f"Parseados: {len(detections)} detecciones, "
          f"{len(mitigations)} mitigaciones, {len(unblocks)} desbloqueos")

    records = compute_stats(detections, mitigations, unblocks)
    summarize(records)

    if args.csv:
        fields = ["scenario", "domain", "attack_type", "src", "dst",
                  "detection_at", "mitigation_at", "unblock_at", "Tm_s", "Tu_s"]
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in records:
                w.writerow({"scenario": args.scenario or "", **r})
        print(f"CSV guardado: {args.csv}")


if __name__ == "__main__":
    main()
