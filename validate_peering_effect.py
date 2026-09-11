#!/usr/bin/env python3
"""
validate_peering_effect.py -- confirms the BGP Peering domain's FlowSpec
mitigation has a REAL effect on traffic, not just that an nftables rule
exists (docs/peering-plan.md §6's outstanding "efecto medido" criterion).

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
from topologies.star_topology import CENTRAL_SERVER_IP, EXTERNAL_PEER_IP  # noqa: E402
from webtool.orchestrator import Orchestrator, CONTROLLER_LOG_PATH  # noqa: E402

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
        print(f"\n=== 3. Lanzando flood SYN real (bgp) desde peer_ext -> "
              f"central_server ({ATTACK_DURATION_S}s) ===")
        result = orchestrator.start_peering_attack(
            "SYN", 443, CENTRAL_SERVER_IP, duration=ATTACK_DURATION_S,
        )
        all_ok &= check("start_peering_attack() ok", result.get("ok", False))

        wait_s = ATTACK_DURATION_S + POST_ATTACK_WAIT_S
        print(f"    esperando {wait_s}s (duracion del ataque + margen de "
              f"telemetria) mientras el motor de deteccion real decide...")
        time.sleep(wait_s)

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

        print("\n=== 5. Decodificando capturas nfcapd y comparando trafico de respuesta ===")
        records = _decode_nfcapd_dir(settings.PEERING_NFCAPD_DIR, settings.PEERING_NFDUMP_BIN)
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

    finally:
        print("\n=== 6. Apagando (stop_topology + stop_controller) ===")
        orchestrator.stop_topology()
        orchestrator.stop_controller()
        check("teardown completado", True)

    return all_ok


if __name__ == "__main__":
    ok = main()
    print(f"\n{'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
