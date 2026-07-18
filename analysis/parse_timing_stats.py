#!/usr/bin/env python3
"""
analysis/parse_timing_stats.py

Extrae estadísticas de tiempos del log unificado del controlador
(/tmp/webtool_controller.log), que contiene tanto la salida de
ryu-manager como los eventos del webtool.

  Td  — Tiempo de detección: desde ATTACK_START hasta ATTACK_DETECTED
         para el mismo target_ip.

  Tm  — Tiempo de mitigación: desde ATTACK_DETECTED hasta BLOCK/THROTTLE
         para el mismo (domain, dst_ip).

  Tu  — Tiempo de bloqueo activo: desde BLOCK/THROTTLE hasta
         UNBLOCK/UNTHROTTLE para la misma (src_ip, domain).

Uso:
  python3 analysis/parse_timing_stats.py /tmp/webtool_controller.log
  python3 analysis/parse_timing_stats.py /tmp/webtool_controller.log --scenario 5d
  python3 analysis/parse_timing_stats.py /tmp/webtool_controller.log --scenario 5d --csv out.csv

El script busca automáticamente /tmp/webtool_events.log junto al log del controlador.
Se puede especificar otra ruta con --events-log.

Con --scenario se acota el análisis a la ventana temporal del escenario:
  desde el primer ATTACK_START con scenario=<ID>
  hasta el primer ATTACK_START de otro escenario distinto (o fin del log).

Archivos:
  webtool_controller.log — stdout de ryu-manager (DETECTION, MITIGATION, etc.)
  webtool_events.log     — eventos del webtool (ATTACK_START, ATTACK_STOP, etc.)
"""

import argparse
import csv
import re
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional


_TS_FMT = "%Y-%m-%d %H:%M:%S"

# ── ryu-manager lines ────────────────────────────────────────────────────────

_RYU_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s+\S+"              # level
    r"\s+FlowStatsIDS"
    r"\s+\[(?P<domain>[^\]]+)\]"
    r"\s+(?P<event_type>\w+):"
    r"\s+(?P<message>.+)$"
)

_DETECTION_RE = re.compile(
    r"ATTACK_DETECTED\s+(?P<attack_type>\S+)"
    r"\s+source=(?P<src>\S+)"
    r"\s+destination=(?P<dst>[^:]+):(?P<port>\d+)/(?P<proto>\S+)"
)

_ACTION_RE  = re.compile(r"^(?P<action>BLOCK|THROTTLE|UNBLOCK|UNTHROTTLE)\s+(?P<attack_type>\S+)")
_SRC_IP_RE  = re.compile(r"src_ip=(\S+)")
_SOURCE_RE  = re.compile(r"source=(\S+)")
_DST_RE     = re.compile(r"destination=([^:]+):(\d+)/(\S+)")

# ── webtool lines ─────────────────────────────────────────────────────────────

_WEBTOOL_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s+\S+"              # level
    r"\s+\[webtool\]"
    r"\s+(?P<event_type>\w+):"
    r"\s+(?P<message>.+)$"
)

_ATTACK_START_RE = re.compile(
    r"scenario=(?P<scenario>\S+)"
    r"\s+domain=(?P<domain>\S+)"
    r"\s+switches=(?P<switches>\[[^\]]*\])"
    r"\s+tipo=(?P<attack_type>\S+)"
    r"\s+target=(?P<target_ip>\S+)"
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
        "action": action, "attack_type": attack_type,
        "src": src or "*", "dst": dst, "dst_port": dst_port, "proto": proto,
    }


def parse_events_log(path: str) -> List[dict]:
    """
    Parse /tmp/webtool_events.log — lines written exclusively by webtool/state.py.
    Format: YYYY-MM-DD HH:MM:SS INFO [webtool] EVENT_TYPE: message
    Returns list of ATTACK_START dicts.
    """
    attack_starts = []
    if not path or not __import__("os").path.exists(path):
        return attack_starts
    with open(path, "r") as f:
        for line in f:
            m = _WEBTOOL_LINE_RE.match(line.strip())
            if not m or m.group("event_type") != "ATTACK_START":
                continue
            am = _ATTACK_START_RE.search(m.group("message"))
            if am:
                attack_starts.append({
                    "ts":          _ts(m.group("ts")),
                    "scenario":    am.group("scenario"),
                    "domain":      am.group("domain"),
                    "attack_type": am.group("attack_type"),
                    "target_ip":   am.group("target_ip"),
                })
    return attack_starts


def parse_ryu_log(path: str):
    """
    Parse /tmp/webtool_controller.log — ryu-manager stdout.
    Returns (detections, mitigations, unblocks).
    """
    detections  = []
    mitigations = []
    unblocks    = []

    with open(path, "r") as f:
        for line in f:
            m = _RYU_LINE_RE.match(line.strip())
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


def _scenario_window(attack_starts: list, scenario_id: str):
    """
    Returns (t_start, t_end) for the requested scenario.

    t_start = timestamp of the first ATTACK_START with scenario==scenario_id
    t_end   = timestamp of the first ATTACK_START of a *different* scenario
              that occurs after t_start, or None (= end of log)
    """
    t_start = None
    for ev in attack_starts:
        if ev["scenario"] == scenario_id:
            t_start = ev["ts"]
            break
    if t_start is None:
        return None, None

    t_end = None
    for ev in attack_starts:
        if ev["ts"] <= t_start:
            continue
        if ev["scenario"] != scenario_id:
            t_end = ev["ts"]
            break

    return t_start, t_end


def _filter(events: list, t_start, t_end) -> list:
    return [
        e for e in events
        if e["ts"] >= t_start and (t_end is None or e["ts"] < t_end)
    ]


def _infer_dst(mit: dict, detections: list) -> Optional[str]:
    if mit["dst"]:
        return mit["dst"]
    candidates = [
        d for d in detections
        if d["domain"] == mit["domain"] and d["ts"] <= mit["ts"]
    ]
    return candidates[-1]["dst"] if candidates else None


def compute_stats(attack_starts, detections, mitigations, unblocks):
    records = []

    for mit in mitigations:
        dst    = _infer_dst(mit, detections)
        src    = mit["src"]
        domain = mit["domain"]
        mit_ts = mit["ts"]

        # Td: nearest ATTACK_START for same target_ip within 120s before the
        #     first matching DETECTION.
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

        Td = None
        attack_start_ts = None
        if det_match:
            for atk in reversed(attack_starts):
                if atk["target_ip"] != (dst or ""):
                    continue
                dt = (det_match["ts"] - atk["ts"]).total_seconds()
                if 0.0 <= dt <= 120.0:
                    Td = round(dt, 3)
                    attack_start_ts = atk["ts"]
                    break

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
            "attack_at":     attack_start_ts.strftime(_TS_FMT) if attack_start_ts else "",
            "detection_at":  det_match["ts"].strftime(_TS_FMT) if det_match else "",
            "mitigation_at": mit_ts.strftime(_TS_FMT),
            "unblock_at":    unblock_match["ts"].strftime(_TS_FMT) if unblock_match else "",
            "Td_s":          Td if Td is not None else "",
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

    def _s(vals):
        if not vals:
            return None
        return sum(vals) / len(vals), min(vals), max(vals), len(vals)

    for domain, recs in sorted(by_domain.items()):
        tds = [r["Td_s"] for r in recs if r["Td_s"] != ""]
        tms = [r["Tm_s"] for r in recs if r["Tm_s"] != ""]
        tus = [r["Tu_s"] for r in recs if r["Tu_s"] != ""]
        print(f"\n  Dominio: {domain.upper()}  ({len(recs)} bloques)")
        s = _s(tds)
        if s:
            print(f"    Td (ataque → detección):      media={s[0]:.3f}s  min={s[1]:.3f}s  max={s[2]:.3f}s  n={s[3]}")
        else:
            print(f"    Td: sin datos de inicio de ataque en ventana 120s")
        s = _s(tms)
        if s:
            print(f"    Tm (detección → mitigación):   media={s[0]:.3f}s  min={s[1]:.3f}s  max={s[2]:.3f}s  n={s[3]}")
        else:
            print(f"    Tm: sin DETECTION en ventana 60s antes del bloque")
        s = _s(tus)
        if s:
            print(f"    Tu (mitigación → desbloqueo):  media={s[0]:.1f}s  min={s[1]:.1f}s  max={s[2]:.1f}s  n={s[3]}")
        else:
            print(f"    Tu: sin desbloqueos registrados")

    all_tds = [r["Td_s"] for r in records if r["Td_s"] != ""]
    all_tms = [r["Tm_s"] for r in records if r["Tm_s"] != ""]
    all_tus = [r["Tu_s"] for r in records if r["Tu_s"] != ""]
    print(f"\n  TOTAL  ({len(records)} bloques)")
    s = _s(all_tds)
    if s:
        print(f"    Td: media={s[0]:.3f}s  min={s[1]:.3f}s  max={s[2]:.3f}s")
    s = _s(all_tms)
    if s:
        print(f"    Tm: media={s[0]:.3f}s  min={s[1]:.3f}s  max={s[2]:.3f}s")
    s = _s(all_tus)
    if s:
        print(f"    Tu: media={s[0]:.1f}s  min={s[1]:.1f}s  max={s[2]:.1f}s")
    print()


_DEFAULT_EVENTS_LOG = "/tmp/webtool_events.log"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("log", help="Ruta al log del controlador (ej. /tmp/webtool_controller.log)")
    ap.add_argument("--events-log", metavar="FILE", default=_DEFAULT_EVENTS_LOG,
                    help=f"Ruta al log de eventos del webtool (default: {_DEFAULT_EVENTS_LOG})")
    ap.add_argument("--scenario", metavar="ID",
                    help="Acotar análisis al escenario indicado (ej. '5d'). "
                         "Ventana: desde primer ATTACK_START del escenario hasta "
                         "el primer ATTACK_START de otro escenario.")
    ap.add_argument("--csv", metavar="FILE", help="Exportar CSV detallado")
    args = ap.parse_args()

    attack_starts           = parse_events_log(args.events_log)
    detections, mitigations, unblocks = parse_ryu_log(args.log)
    print(f"Parseados: {len(attack_starts)} inicios de ataque, "
          f"{len(detections)} detecciones, "
          f"{len(mitigations)} mitigaciones, {len(unblocks)} desbloqueos")

    if args.scenario:
        t_start, t_end = _scenario_window(attack_starts, args.scenario)
        if t_start is None:
            print(f"ERROR: no se encontró ningún ATTACK_START con scenario={args.scenario}")
            return
        t_end_str = t_end.strftime(_TS_FMT) if t_end else "fin del log"
        print(f"Ventana escenario {args.scenario}: {t_start.strftime(_TS_FMT)} → {t_end_str}")
        attack_starts = _filter(attack_starts, t_start, t_end)
        detections    = _filter(detections,    t_start, t_end)
        mitigations   = _filter(mitigations,   t_start, t_end)
        unblocks      = _filter(unblocks,      t_start, t_end)

    records = compute_stats(attack_starts, detections, mitigations, unblocks)
    summarize(records)

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
