#!/usr/bin/env python3
"""
validate_peering_effect.py -- the formal end-to-end test case for the
BGP Peering domain's basic single-source SYN/DoS scenario
(docs/peering-plan.md §5, punto 6; one of the "24 combinaciones
basicas" cuatro-dominios x tres-vectores x DoS/DDoS matrix in
docs/thesis-revision-plan.md §4.3-4.4.3). Confirms the FlowSpec
mitigation has a REAL effect on traffic, not just that an nftables
rule exists, and reports all four formal timing metrics from
docs/thesis-revision-plan.md §4.5-4.6's table: Tiempo de deteccion
(Td), Tiempo de despacho (Tm), Tiempo de aplicacion, Tiempo hasta
efecto.

Unlike validate_peering.py (which drives mitigation/peering_backend.py's
announce()/withdraw() directly, bypassing detection entirely), this
script drives the REAL stack end to end: webtool/orchestrator.py's
Orchestrator starts the actual ryu-manager subprocess (the same one the
webtool UI uses) and the real Mininet topology, then launches a genuine
hping3 SYN flood from peer_ext against central_server and lets the
detection engine decide when to announce/withdraw the FlowSpec route on
its own.

Why "effect" can't be measured from the attacker's own inbound traffic:
softflowd's capture on r1-ext0 happens at the packet-capture layer,
BEFORE nftables ever renders a verdict -- the attacker's own packets
show up in nfcapd captures at the same rate whether the FlowSpec rule
is active or not (this is exactly why the bgp domain needed
PRESENCE_BLIND_DOMAINS treatment for its own unblock logic, see
config/settings.py). What DOES depend on the block actually taking
effect is r1's own REPLY traffic: a SYN arriving at a closed TCP port
normally gets an immediate kernel-generated RST sent back out
(confirmed on the VM in earlier manual testing) -- but only if the
packet ever reaches local delivery. If the FlowSpec rule drops it
first, no RST is ever generated. So the real-effect signal this script
checks is: does central_server's own RST-reply traffic disappear from
nfcapd captures during the block window, and reappear once the
BGP_FLOWSPEC_DISCARD route auto-expires (config.settings' bgp TTL,
see docs/peering-plan.md §6)?

Td and Tm come from analysis/parse_timing_stats.py's own functions --
that script already computes these generically per domain from the
same two log files this run produces, it just needed
BGP_FLOWSPEC_DISCARD added alongside BLOCK/THROTTLE as a recognized
mitigation-action string (its regex only knew about the other domains'
action names). Tiempo de aplicacion and Tiempo hasta efecto are
derived here from data this script already collects for the effect
measurement above (the nft-ruleset poll timeline and the reply-traffic
timeline, respectively) -- see _t_apply()/_t_efecto()'s own docstrings
for exactly how each is defined and bounded.

Prerequisites: same as webtool/app.py -- run as root, deploy/
install_bgp_peering.sh already run, and the usual stale-process
cleanup (pkill -9 -f "flow run"/exabgp/softflowd/nfcapd/ryu-manager,
ip link del veth-peering0, sudo mn -c) done beforehand -- this script
does not attempt that cleanup itself, same convention validate_peering.py
already follows.

Usage:
  sudo python3 validate_peering_effect.py
"""
import csv
import io
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_DIR))

import config.settings as settings  # noqa: E402
from analysis.parse_timing_stats import (  # noqa: E402
    parse_events_log, parse_ryu_log, compute_stats, summarize,
)
from topologies.star_topology import CENTRAL_SERVER_IP, EXTERNAL_PEER_IP  # noqa: E402
from webtool.orchestrator import Orchestrator, CONTROLLER_LOG_PATH, EVENTS_LOG_PATH  # noqa: E402

# Long enough to span: detection latency (~12s, see docs/peering-plan.md
# §2.3), a full block window (config.settings' bgp MitigationAction
# duration, currently 60s via the dataclass default -- see
# core/models.py), and enough of the re-opened gap afterward to catch
# the reply traffic actually resuming before any re-block.
ATTACK_DURATION_S = 100
# Extra time after the attack's own auto-stop for the last nfcapd
# rotation (5s interval, needs to be no longer the "last" file -- see
# collectors/peering_flow_collector.py) and one more detection cycle.
POST_ATTACK_WAIT_S = 15
# How often to poll `nft list ruleset` on r1 during the wait, to catch a
# real-time rule presence/absence flip (see the "45-48s gap" comment
# where this gets used) -- cheap enough to run every second without
# meaningfully perturbing anything.
RULE_POLL_INTERVAL_S = 1.0
# Minimum gap with zero reply-direction records to count as a genuine,
# persistent traffic reduction for Tefecto (docs/thesis-revision-plan.md
# §4.5-4.6's "Tiempo hasta efecto": "primera reduccion que cumple
# criterio persistente menos inicio del ataque"). Comfortably above the
# ~2-3s spacing normal continuous traffic produces under softflowd's
# general=1/maxlife=2 timeouts (see webtool/peering_ops.py), comfortably
# below the ~45s mark of the known, unresolved leak (docs/peering-plan.md
# §6) -- a real block-onset gap (tens of seconds) registers as
# "sustained" long before that leak could interrupt it; a short-lived
# leak that breaks up what should be one long gap into shorter pieces
# will correctly fail to qualify until past it, which is the honest
# behavior wanted here, not a bug to work around.
EFFECT_GAP_THRESHOLD_S = 8.0

_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
_FMT = "%Y-%m-%d %H:%M:%S"


def check(label: str, ok: bool) -> bool:
    print(f"  [{'OK' if ok else 'FALLO'}] {label}")
    return ok


def _parse_log_events(text: str):
    """(datetime, 'DISCARD'|'WITHDRAWN') for every matching controller log line, in order."""
    events = []
    for line in text.splitlines():
        m = _TS_RE.match(line)
        if not m:
            continue
        ts = datetime.strptime(m.group(1), _FMT)
        if "BGP_FLOWSPEC_DISCARD" in line:
            events.append((ts, "DISCARD"))
        elif "FLOWSPEC_WITHDRAWN" in line:
            events.append((ts, "WITHDRAWN"))
    return events


def _block_intervals(events):
    """Pairs consecutive DISCARD/WITHDRAWN events into [(start, end), ...] windows.
    A DISCARD with no matching WITHDRAWN yet (still active at analysis time)
    is left open-ended (end=None)."""
    intervals = []
    open_start = None
    for ts, kind in events:
        if kind == "DISCARD" and open_start is None:
            open_start = ts
        elif kind == "WITHDRAWN" and open_start is not None:
            intervals.append((open_start, ts))
            open_start = None
    if open_start is not None:
        intervals.append((open_start, None))
    return intervals


def _decode_nfcapd_dir(capture_dir: str, nfdump_bin: str):
    """(datetime, src_ip, dst_ip, td, ipkt, ibyt, file) for every flow record
    across every capture file currently in the directory -- this script
    reads the WHOLE directory after the test, not collectors/
    peering_flow_collector.py's own live-polling "skip the last file"
    semantics (irrelevant here, every file involved is long since rotated
    by the time this runs). Packet/byte/duration fields carried through so
    any stray inside-block record can be inspected for its actual size,
    not just its existence.
    """
    records = []
    for path in sorted(Path(capture_dir).glob("nfcapd.*")):
        if path.name.startswith("nfcapd.current."):
            continue
        try:
            result = subprocess.run(
                [nfdump_bin, "-r", str(path), "-o", "csv"],
                capture_output=True, text=True, timeout=30, check=True,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        for row in csv.DictReader(io.StringIO(result.stdout)):
            ts_raw = row.get("ts", "")
            sa, da = row.get("sa"), row.get("da")
            if not ts_raw or not sa or not da:
                continue
            try:
                ts = datetime.strptime(ts_raw[:19], _FMT)
                td = float(row.get("td", 0) or 0)
                ipkt = int(row.get("ipkt", 0) or 0)
                ibyt = int(row.get("ibyt", 0) or 0)
            except (ValueError, TypeError):
                continue
            records.append((ts, sa, da, td, ipkt, ibyt, path.name))
    return records


def _t_apply(discard_ts, rule_transitions):
    """
    Tiempo de aplicacion (docs/thesis-revision-plan.md §4.5-4.6):
    "instalacion comprobada menos envio". `discard_ts` is when the
    controller decided+sent the announcement (BGP_FLOWSPEC_DISCARD in
    its own log); the first RULE_PRESENT transition at or after that is
    the earliest confirmed installation this script observed. Bounded
    below by RULE_POLL_INTERVAL_S -- report that explicitly rather than
    implying sub-second precision the polling can't actually back up.
    """
    for ts, state in rule_transitions:
        if state == "RULE_PRESENT" and ts >= discard_ts:
            return (ts - discard_ts).total_seconds()
    return None


def _t_efecto(attack_start, replies):
    """
    Tiempo hasta efecto (docs/thesis-revision-plan.md §4.5-4.6):
    "primera reduccion que cumple criterio persistente menos inicio del
    ataque". Walks the reply-direction timeline in order and returns the
    timestamp where the first gap of at least EFFECT_GAP_THRESHOLD_S
    with zero reply records begins, provided at least one reply was
    already seen before it (confirming there was real traffic to reduce
    in the first place, not just an empty window). Returns None if no
    such persistent gap is found in the observed data.
    """
    reply_times = sorted(r[0] for r in replies if r[0] >= attack_start)
    if not reply_times:
        return None
    for i in range(len(reply_times) - 1):
        gap = (reply_times[i + 1] - reply_times[i]).total_seconds()
        if gap >= EFFECT_GAP_THRESHOLD_S:
            return (reply_times[i] - attack_start).total_seconds()
    return None


def main() -> bool:
    all_ok = True
    orchestrator = Orchestrator()

    print("=== 1. Arrancando el controlador real (ryu-manager) ===")
    result = orchestrator.start_controller()
    if not check("start_controller() ok", result.get("ok", False)):
        print(f"    {result}")
        return False
    if result.get("adopted"):
        print("    ADVERTENCIA: se adopto un controlador ya corriendo -- "
              "su log puede no estar recien rotado. Se recomienda detener "
              "cualquier ryu-manager previo antes de correr este script.")

    print("\n=== 2. Arrancando la topologia ===")
    result = orchestrator.start_topology()
    if not check("start_topology() ok", result.get("ok", False)):
        print(f"    {result}")
        orchestrator.stop_controller()
        return False

    try:
        run_start = datetime.now()
        print(f"\n=== 3. Lanzando flood SYN real (bgp) desde peer_ext -> "
              f"central_server ({ATTACK_DURATION_S}s) ===")
        result = orchestrator.start_peering_attack(
            "SYN", 443, CENTRAL_SERVER_IP, duration=ATTACK_DURATION_S,
        )
        all_ok &= check("start_peering_attack() ok", result.get("ok", False))

        wait_s = ATTACK_DURATION_S + POST_ATTACK_WAIT_S
        print(f"    esperando {wait_s}s (duracion del ataque + margen de "
              f"telemetria) mientras el motor de deteccion real decide -- "
              f"vigilando el estado real de la regla nftables cada "
              f"{RULE_POLL_INTERVAL_S}s...")
        # An earlier run found a full-volume reply burst ~45-48s into a
        # 60s block window, on TWO independent runs -- not a couple of
        # stray packets, a real gap. Polling `nft list ruleset` directly
        # (not just trusting the controller's own DISCARD/WITHDRAWN log
        # lines) tells us whether the rule itself briefly disappears from
        # the kernel during that gap (a `flow` reliability issue) or stays
        # installed the whole time (pointing elsewhere, e.g. conntrack).
        rule_transitions = []
        last_state = None
        deadline = time.time() + wait_s
        while time.time() < deadline:
            ruleset = orchestrator.r1.cmd("nft list ruleset")
            present = CENTRAL_SERVER_IP in ruleset
            if present != last_state:
                rule_transitions.append((datetime.now(), "RULE_PRESENT" if present else "RULE_ABSENT"))
                last_state = present
            time.sleep(RULE_POLL_INTERVAL_S)

        print("\n=== 4. Leyendo el log del controlador ===")
        log_text = Path(CONTROLLER_LOG_PATH).read_text()
        events = _parse_log_events(log_text)
        discards = [e for e in events if e[1] == "DISCARD"]
        withdrawals = [e for e in events if e[1] == "WITHDRAWN"]
        all_ok &= check(
            f"al menos 1 BGP_FLOWSPEC_DISCARD real (motor de deteccion) visto "
            f"({len(discards)})", len(discards) >= 1,
        )
        for ts, kind in events:
            print(f"    {ts}  {kind}")

        intervals = _block_intervals(events)
        if not intervals:
            check("al menos una ventana de bloqueo completa (DISCARD->WITHDRAWN)", False)
            all_ok = False
        else:
            print(f"    ventanas de bloqueo detectadas: {len(intervals)}")

        print(f"\n    estado real de 'nft list ruleset' en r1 (polling cada "
              f"{RULE_POLL_INTERVAL_S}s durante la espera):")
        for ts, state in rule_transitions:
            print(f"      {ts.strftime(_FMT)}  {state}")
        if not rule_transitions:
            print("      (nunca se detecto la regla presente durante el polling)")

        print("\n=== 5. Decodificando capturas nfcapd y comparando trafico de respuesta ===")
        # PEERING_NFCAPD_DIR accumulates capture files across every past
        # test session (nfcapd only prunes by its own retention window,
        # not by "this script's" lifetime) -- confirmed on the VM: an
        # unfiltered read here mixed in reply records from hours-old
        # sessions as if they were this run's own "before the block"
        # baseline. Only records from at or after this run's own start
        # are this test's.
        records = [
            r for r in _decode_nfcapd_dir(settings.PEERING_NFCAPD_DIR, settings.PEERING_NFDUMP_BIN)
            if r[0] >= run_start
        ]
        replies = [
            r for r in records
            if r[1] == CENTRAL_SERVER_IP and r[2] == EXTERNAL_PEER_IP
        ]
        print(f"    registros totales decodificados: {len(records)}, "
              f"de respuesta (central_server -> peer_ext): {len(replies)}")

        def _inside_any_interval(ts) -> bool:
            for start, end in intervals:
                if start <= ts <= (end or datetime.max):
                    return True
            return False

        replies_inside = [r for r in replies if _inside_any_interval(r[0])]
        replies_outside = [r for r in replies if not _inside_any_interval(r[0])]

        pkts_outside = sum(r[4] for r in replies_outside)
        pkts_inside = sum(r[4] for r in replies_inside)

        all_ok &= check(
            f"trafico de respuesta visto FUERA de la ventana de bloqueo "
            f"({len(replies_outside)} registros, {pkts_outside} paquetes -- "
            f"confirma que central_server responde normalmente sin el "
            f"bloqueo activo)",
            len(replies_outside) > 0,
        )
        all_ok &= check(
            f"CERO trafico de respuesta visto DENTRO de la ventana de bloqueo "
            f"({len(replies_inside)} registros, {pkts_inside} paquetes -- "
            f"confirma que el paquete se descarta de verdad, no solo que la "
            f"regla existe)",
            len(replies_inside) == 0,
        )
        print(f"    detalle completo, fuera del bloqueo (linea base para comparar):")
        for ts, sa, da, td, ipkt, ibyt, fname in replies_outside:
            print(f"      {ts}  {sa} -> {da}  td={td:.3f}s ipkt={ipkt} ibyt={ibyt}  ({fname})")
        if replies_inside:
            print("    registros de respuesta inesperados DENTRO del bloqueo:")
            for ts, sa, da, td, ipkt, ibyt, fname in replies_inside:
                print(f"      {ts}  {sa} -> {da}  td={td:.3f}s ipkt={ipkt} ibyt={ibyt}  ({fname})")

        print("\n=== 6. Metricas formales de tiempo (docs/thesis-revision-plan.md §4.5-4.6) ===")
        # Reuses analysis/parse_timing_stats.py's own generic, per-domain
        # computation against the exact same two log files this run just
        # produced -- Td (ataque->deteccion) and Tm (deteccion->mitigacion,
        # i.e. "Tiempo de despacho": envio de orden menos decision). That
        # script only needed BGP_FLOWSPEC_DISCARD recognized alongside
        # BLOCK/THROTTLE as a mitigation-action string to already work
        # for this domain.
        attack_starts_ts = parse_events_log(EVENTS_LOG_PATH)
        ts_detections, ts_mitigations, ts_unblocks = parse_ryu_log(CONTROLLER_LOG_PATH)
        timing_records = compute_stats(attack_starts_ts, ts_detections, ts_mitigations, ts_unblocks)
        bgp_timing_records = [r for r in timing_records if r["domain"] == "bgp"]
        all_ok &= check(
            f"al menos 1 registro de timing bgp con Td/Tm calculados "
            f"({len(bgp_timing_records)} en total)",
            any(r["Td_s"] != "" and r["Tm_s"] != "" for r in bgp_timing_records),
        )
        summarize(timing_records)

        t_apply = _t_apply(discards[0][0], rule_transitions) if discards else None
        t_efecto = _t_efecto(run_start, replies)

        print("    Reporte formal (caso: bgp / SYN / DoS monofuente, ataque real via peer_ext):")
        if bgp_timing_records:
            r0 = bgp_timing_records[0]
            print(f"      Tiempo de deteccion (Td):    {r0['Td_s']}s")
            print(f"      Tiempo de despacho (Tm):     {r0['Tm_s']}s")
        if t_apply is not None:
            print(f"      Tiempo de aplicacion:        {t_apply:.3f}s "
                  f"(cota superior -- resolucion de polling {RULE_POLL_INTERVAL_S}s)")
        else:
            print("      Tiempo de aplicacion:        sin dato (no se observo RULE_PRESENT tras el DISCARD)")
        if t_efecto is not None:
            print(f"      Tiempo hasta efecto:         {t_efecto:.3f}s "
                  f"(primer hueco >= {EFFECT_GAP_THRESHOLD_S:.0f}s sin trafico de respuesta)")
        else:
            print(f"      Tiempo hasta efecto:         sin dato (ningun hueco >= "
                  f"{EFFECT_GAP_THRESHOLD_S:.0f}s encontrado -- ver hallazgo de la fuga en "
                  f"docs/peering-plan.md §6 si esto ocurre en una corrida por lo demas limpia)")
        all_ok &= check(
            "Tiempo de aplicacion y Tiempo hasta efecto calculados",
            t_apply is not None and t_efecto is not None,
        )

    finally:
        print("\n=== 7. Apagando (stop_topology + stop_controller) ===")
        orchestrator.stop_topology()
        orchestrator.stop_controller()
        check("teardown completado", True)

    return all_ok


if __name__ == "__main__":
    ok = main()
    print(f"\n{'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
