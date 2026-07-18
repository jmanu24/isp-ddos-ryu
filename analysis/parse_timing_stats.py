#!/usr/bin/env python3
"""
analysis/parse_timing_stats.py

Extrae estadísticas de tiempos del log del controlador (ryu-manager)
y, opcionalmente, del log del webtool (/tmp/webtool_controller.log):

  Td  — Tiempo de detección: desde "Ataque iniciado" (webtool log)
         hasta primera DETECTION para el mismo target_ip.
         Solo disponible si se pasa --webtool-log.

  Tm  — Tiempo de mitigación: desde primera DETECTION hasta primera
         BLOCK/THROTTLE para el mismo (domain, dst_ip).

  Tu  — Tiempo de bloqueo activo: desde primera BLOCK/THROTTLE hasta
         UNBLOCK/UNTHROTTLE para la misma (src_ip, domain).

Uso:
  python3 analysis/parse_timing_stats.py <ryu.log>
  python3 analysis/parse_timing_stats.py <ryu.log> --webtool-log /tmp/webtool_controller.log
  python3 analysis/parse_timing_stats.py <ryu.log> --webtool-log /tmp/webtool_controller.log \\
          --csv out.csv --scenario 5d

Formato del ryu log:
  YYYY-MM-DD HH:MM:SS LEVEL FlowStatsIDS [domain] EVENT_TYPE: ...

Formato del webtool log:
  YYYY-MM-DD HH:MM:SS Ataque iniciado [domain] switches=[...] tipo=<TYPE> -> <TARGET_IP>
"""

import argparse
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional


_TS_FMT = "%Y-%m-%d %H:%M:%S"

# --- ryu-manager log ---

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

_ACTION_RE = re.compile(
    r"^(?P<action>BLOCK|THROTTLE|UNBLOCK|UNTHROTTLE)\s+(?P<attack_type>\S+)"
)
_SRC_IP_RE = re.compile(r"src_ip=(\S+)")
_SOURCE_RE  = re.compile(r"source=(\S+)")
_DST_RE     = re.compile(r"destination=([^:]+):(\d+)/(\S+)")

# --- webtool log ---

_WEBTOOL_ATTACK_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s+Ataque iniciado"
    r"\s+\[(?P<domain>[^\]]+)\]"
    r"\s+switches=(?P<switches>\[[^\]]*\])"
    r"\s+tipo=(?P<attack_type>\S+)"
    r"\s+->\s+(?P<target_ip>\S+)"
)


def _ts(s: str) -> datetime:
    return datetime.strptime(s, _TS_FMT)


def _parse_action_msg(msg: str) -> Optional[dict]:
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


def parse_ryu_log(path: str):
    detections  = []
    mitigations = []
    unblocks    = []

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


def parse_webtool_log(path: str) -> List[dict]:
    """
    Returns list of attack-start events:
      {ts, domain, attack_type, target_ip, switches}
    """
    attacks = []
    with open(path, "r") as f:
        for line in f:
            m = _WEBTOOL_ATTACK_RE.match(line.strip())
            if m:
                attacks.append({
                    "ts":          _ts(m.group("ts")),
                    "domain":      m.group("domain"),
                    "attack_type": m.group("attack_type"),
                    "target_ip":   m.group("target_ip"),
                    "switches":    m.group("switches"),
                })
    return attacks


def _infer_dst(mit: dict, detections: list) -> Optional[str]:
    if mit["dst"]:
        return mit["dst"]
    candidates = [
        d for d in detections
        if d["domain"] == mit["domain"] and d["ts"] <= mit["ts"]
    ]
    if candidates:
        return candidates[-1]["dst"]
    return None


def compute_stats(detections, mitigations, unblocks, attack_starts=None):
    """
    Returns one record per BLOCK/THROTTLE event with Td (optional), Tm, Tu.
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
                break

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

        # Td: nearest attack-start for same target_ip within 120s before detection.
        Td = None
        attack_start_ts = None
        if attack_starts and det_match:
            for atk in reversed(attack_starts):
                if atk["target_ip"] != (dst or ""):
                    continue
                dt = (det_match["ts"] - atk["ts"]).total_seconds()
                if 0.0 <= dt <= 120.0:
                    Td = round(dt, 3)
                    attack_start_ts = atk["ts"]
                    break

        records.append({
            "domain":        domain,
            "attack_type":   mit["attack_type"],
            "src":           src,
            "dst":           dst or "",
            "attack_at":     attack_start_ts.strftime(_TS_FMT) if attack_start_ts else "",
            "detection_at":  det_match["ts"].strftime(_TS_FMT) if det_match else "",
            "mitigation_at": mit_ts.strftime(_TS_FMT),
            "unblock_at":    unblock_match["ts"].strftime(_TS_FMT) if unblock_match else "",
            "Td_s":          Td if Td is not None else "",
            "Tm_s":          Tm if Tm is not None else "",
            "Tu_s":          Tu if Tu is not None else "",
        })

    return records


def summarize(records, has_td: bool):
    by_domain: Dict[str, list] = defaultdict(list)
    for r in records:
        by_domain[r["domain"]].append(r)

    print(f"\n{'='*70}")
    print(f"{'RESUMEN DE TIEMPOS':^70}")
    print(f"{'='*70}")

    def _stats(vals):
        if not vals:
            return None
        return sum(vals) / len(vals), min(vals), max(vals), len(vals)

    for domain, recs in sorted(by_domain.items()):
        tds = [r["Td_s"] for r in recs if r["Td_s"] != ""]
        tms = [r["Tm_s"] for r in recs if r["Tm_s"] != ""]
        tus = [r["Tu_s"] for r in recs if r["Tu_s"] != ""]
        n   = len(recs)
        print(f"\n  Dominio: {domain.upper()}  ({n} bloques)")
        if has_td:
            s = _stats(tds)
            if s:
                print(f"    Td (ataque → detección):      media={s[0]:.3f}s  min={s[1]:.3f}s  max={s[2]:.3f}s  n={s[3]}")
            else:
                print(f"    Td: sin datos de inicio de ataque en ventana 120s")
        s = _stats(tms)
        if s:
            print(f"    Tm (detección → mitigación):   media={s[0]:.3f}s  min={s[1]:.3f}s  max={s[2]:.3f}s  n={s[3]}")
        else:
            print(f"    Tm: sin datos de detección previos en ventana 60s")
        s = _stats(tus)
        if s:
            print(f"    Tu (mitigación → desbloqueo):  media={s[0]:.1f}s  min={s[1]:.1f}s  max={s[2]:.1f}s  n={s[3]}")
        else:
            print(f"    Tu: sin desbloqueos registrados")

    all_tds = [r["Td_s"] for r in records if r["Td_s"] != ""]
    all_tms = [r["Tm_s"] for r in records if r["Tm_s"] != ""]
    all_tus = [r["Tu_s"] for r in records if r["Tu_s"] != ""]
    print(f"\n  TOTAL  ({len(records)} bloques)")
    if has_td:
        s = _stats(all_tds)
        if s:
            print(f"    Td: media={s[0]:.3f}s  min={s[1]:.3f}s  max={s[2]:.3f}s")
    s = _stats(all_tms)
    if s:
        print(f"    Tm: media={s[0]:.3f}s  min={s[1]:.3f}s  max={s[2]:.3f}s")
    s = _stats(all_tus)
    if s:
        print(f"    Tu: media={s[0]:.1f}s  min={s[1]:.1f}s  max={s[2]:.1f}s")
    print()


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("log", help="Ruta al log de ryu-manager")
    ap.add_argument("--webtool-log", metavar="FILE",
                    help="Ruta al log del webtool (/tmp/webtool_controller.log) "
                         "para calcular Td (ataque → detección)")
    ap.add_argument("--csv", metavar="FILE", help="Exportar CSV detallado")
    ap.add_argument("--scenario", metavar="LABEL",
                    help="Etiqueta de escenario para el CSV (ej. '5d')")
    args = ap.parse_args()

    detections, mitigations, unblocks = parse_ryu_log(args.log)
    print(f"Parseados: {len(detections)} detecciones, "
          f"{len(mitigations)} mitigaciones, {len(unblocks)} desbloqueos")

    attack_starts = None
    if args.webtool_log:
        attack_starts = parse_webtool_log(args.webtool_log)
        print(f"Webtool log: {len(attack_starts)} ataques iniciados")

    records = compute_stats(detections, mitigations, unblocks, attack_starts)
    summarize(records, has_td=attack_starts is not None)

    if args.csv:
        fields = ["scenario", "domain", "attack_type", "src", "dst",
                  "attack_at", "detection_at", "mitigation_at", "unblock_at",
                  "Td_s", "Tm_s", "Tu_s"]
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in records:
                w.writerow({"scenario": args.scenario or "", **r})
        print(f"CSV guardado: {args.csv}")


if __name__ == "__main__":
    main()
