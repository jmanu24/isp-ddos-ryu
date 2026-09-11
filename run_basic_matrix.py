#!/usr/bin/env python3
"""
run_basic_matrix.py -- automates the "24 combinaciones basicas" test
matrix from docs/thesis-revision-plan.md SS4.3-4.4.3: cuatro dominios
(enterprise, mobile, broadband, bgp) x tres vectores (SYN, UDP, ICMP) x
DoS/DDoS.

Drives webtool/orchestrator.py's Orchestrator directly (the same class
webtool/app.py's Flask routes use), the same pattern
validate_peering_effect.py already established: one real ryu-manager
subprocess, one real Mininet topology, real attack traffic (hping3 from
real/spoofed Mininet hosts, real BNGBlaster sessions), the real
detection/decision/mitigation pipeline deciding on its own -- nothing in
this script's own process ever calls into detection/mitigation code
directly.

Each of the 24 domain/vector/mode combinations is fired as its OWN
webtool "scenario" (a unique scenario_id per combination), sequentially,
never overlapping -- analysis/parse_timing_stats.py's own scenario-
window mechanism (an ATTACK_START's own scenario= tag, up to the next
DIFFERENT scenario's ATTACK_START) is what isolates each combination's
Td/Tm/Tu from every other one in the shared controller/events logs, so
combinations must not overlap in time or that isolation breaks.

What "DDoS" means per domain (see docs/peering-plan.md and this
project's own README/memory for the full reasoning -- summarized here):
  - enterprise: all TOPOLOGY_NUM_SWITCHES real hosts attack at once (one
    real, unspoofed source per switch) -- config/settings.py's
    TOPOLOGY_NUM_SWITCHES was raised from 4 to 5 specifically so this
    can cross DIST_MIN_SOURCES=5.
  - mobile: one gNB, count_per_gnb=DIST_MIN_SOURCES spoofed UEs (each a
    distinct source IP) attacking through it.
  - broadband: the dedicated distributed_* BNGBlaster scenario for that
    vector (8 sessions each, simulation/bng_config.py).
  - bgp: peer_ext's own hping3 flood with --rand-source (spoofed=True)
    -- the only way a domain with exactly one real external host can
    ever produce >=DIST_MIN_SOURCES distinct source IPs. Relies on
    telemetry/bgp_adapter.py's DENYLIST-based source filtering (not an
    allowlist of peer_ext's own real IP), see config/settings.py's
    PEERING_CENTRAL_SERVER_IP comment.

Every combination attacks central_server (topologies/star_topology.py's
CENTRAL_SERVER_IP) -- the only destination where the bgp domain reliably
wins correlation over enterprise (docs/peering-plan.md SS2.4's documented
architectural limitation), so central_server is used uniformly across
all 24 combinations for a fair, consistent comparison rather than a
different target per domain.

Usage:
  sudo python3 run_basic_matrix.py [--csv matrix_results.csv]

Prerequisites: same as webtool/app.py -- run as root, deploy/
install_bgp_peering.sh already run, and the usual stale-process cleanup
(pkill -9 -f "flow run"/exabgp/softflowd/nfcapd/ryu-manager/bngblaster,
ip link del veth-peering0/veth-n/veth-a, sudo mn -c) done beforehand.
"""
import argparse
import csv as csv_module
import sys
import time
from datetime import datetime
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_DIR))

import config.settings as settings  # noqa: E402
from analysis.parse_timing_stats import (  # noqa: E402
    parse_events_log, parse_ryu_log, _scenario_window, _filter, compute_stats,
)
from topologies.star_topology import CENTRAL_SERVER_IP  # noqa: E402
from webtool.orchestrator import Orchestrator, CONTROLLER_LOG_PATH, EVENTS_LOG_PATH  # noqa: E402

DOMAINS = ("enterprise", "mobile", "broadband", "bgp")
VECTORS = ("SYN", "UDP", "ICMP")
MODES = ("DoS", "DDoS")

# Long enough for detection (sub-10s in every domain, per this project's
# own measured history) and mitigation to fire well within the window,
# short enough that 24 back-to-back combinations finish in a reasonable
# unattended run.
ATTACK_DURATION_S = 30
# Every PER_SOURCE_MITIGATION_DOMAINS member (mobile/broadband/bgp, see
# config/settings.py) holds its block for a fixed MitigationAction.duration
# (60s) regardless of when the attack itself stops -- this needs to
# comfortably outlast that hold, counted from whenever mitigation fires
# (typically within the first few seconds of the attack), not from when
# the attack ends. enterprise's presence-based unblock is far faster
# (fires once real attack traffic disappears) and easily fits inside the
# same window.
TOTAL_WAIT_S = 90

ATTACK_TYPE_TO_DST_PORT = {"SYN": 443, "UDP": 0, "ICMP": 0}
_BROADBAND_DISTRIBUTED_TYPE = {"SYN": "SYN_DISTRIBUTED", "UDP": "UDP_DISTRIBUTED", "ICMP": "ICMP_DISTRIBUTED"}


def check(label: str, ok: bool) -> bool:
    print(f"  [{'OK' if ok else 'FALLO'}] {label}")
    return ok


def _scenario_id(domain: str, vector: str, mode: str) -> str:
    return f"matrix_{domain}_{vector}_{mode}"


def _launch(orchestrator: Orchestrator, domain: str, vector: str, mode: str) -> dict:
    """Fires one (domain, vector, mode) combination's attack and returns
    the underlying start_*_attack() result (always includes 'ok', and
    'attack_id' on success)."""
    scenario_id = _scenario_id(domain, vector, mode)
    dst_port = ATTACK_TYPE_TO_DST_PORT[vector]
    distributed = mode == "DDoS"

    if domain == "enterprise":
        switch_indices = list(range(1, settings.TOPOLOGY_NUM_SWITCHES + 1)) if distributed else [1]
        return orchestrator.start_enterprise_attack(
            switch_indices, vector, dst_port, CENTRAL_SERVER_IP,
            duration=ATTACK_DURATION_S, scenario=scenario_id,
        )

    if domain == "mobile":
        count_per_gnb = settings.DIST_MIN_SOURCES if distributed else 1
        return orchestrator.start_mobile_attack(
            [1], vector, dst_port, CENTRAL_SERVER_IP, count_per_gnb=count_per_gnb,
            duration=ATTACK_DURATION_S, scenario=scenario_id,
        )

    if domain == "broadband":
        attack_type = _BROADBAND_DISTRIBUTED_TYPE[vector] if distributed else vector
        return orchestrator.start_broadband_attack(
            [1], attack_type, CENTRAL_SERVER_IP,
            duration=ATTACK_DURATION_S, scenario=scenario_id,
        )

    if domain == "bgp":
        return orchestrator.start_peering_attack(
            vector, dst_port, CENTRAL_SERVER_IP,
            duration=ATTACK_DURATION_S, scenario=scenario_id, spoofed=distributed,
        )

    raise AssertionError(f"unreachable: domain={domain!r}")


def main() -> bool:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", metavar="FILE", default="matrix_results.csv",
                    help="Ruta del CSV de resultados (default: matrix_results.csv)")
    args = ap.parse_args()

    all_ok = True
    orchestrator = Orchestrator()

    print("=== 1. Arrancando el controlador real (ryu-manager) ===")
    result = orchestrator.start_controller()
    if not check("start_controller() ok", result.get("ok", False)):
        print(f"    {result}")
        return False

    print(f"\n=== 2. Arrancando la topologia ({settings.TOPOLOGY_NUM_SWITCHES} switches) ===")
    result = orchestrator.start_topology()
    if not check("start_topology() ok", result.get("ok", False)):
        print(f"    {result}")
        orchestrator.stop_controller()
        return False

    combos = [(d, v, m) for d in DOMAINS for v in VECTORS for m in MODES]
    print(f"\n=== 3. Corriendo {len(combos)} combinaciones, una a la vez "
          f"({ATTACK_DURATION_S}s de ataque + espera hasta {TOTAL_WAIT_S}s total c/u) ===")

    try:
        for i, (domain, vector, mode) in enumerate(combos, start=1):
            scenario_id = _scenario_id(domain, vector, mode)
            print(f"\n  [{i}/{len(combos)}] {domain} / {vector} / {mode}  (scenario={scenario_id})")
            t0 = datetime.now()
            result = _launch(orchestrator, domain, vector, mode)
            ok = check(f"    lanzado", result.get("ok", False))
            all_ok &= ok
            if not ok:
                print(f"      {result}")
                continue

            attack_id = result["attack_id"]
            time.sleep(TOTAL_WAIT_S)
            # Belt-and-suspenders: the orchestrator's own duration timer
            # should have already auto-stopped this, but broadband in
            # particular refuses a NEW attack while it still thinks one
            # is active (_active_broadband_attack) -- an explicit stop
            # here (harmless no-op if already auto-stopped) guarantees
            # the next combination's start_broadband_attack() won't be
            # rejected because of a timing edge case.
            orchestrator.stop_attack(attack_id)
            print(f"      completado en {(datetime.now() - t0).total_seconds():.0f}s")
    finally:
        print("\n=== 4. Apagando (stop_topology + stop_controller) ===")
        orchestrator.stop_topology()
        orchestrator.stop_controller()
        check("teardown completado", True)

    print("\n=== 5. Analizando resultados (analysis/parse_timing_stats.py) ===")
    attack_starts_all = parse_events_log(EVENTS_LOG_PATH)
    detections_all, mitigations_all, unblocks_all = parse_ryu_log(CONTROLLER_LOG_PATH)

    rows = []
    for domain, vector, mode in combos:
        scenario_id = _scenario_id(domain, vector, mode)
        t_start, t_end = _scenario_window(attack_starts_all, scenario_id)
        if t_start is None:
            rows.append({
                "domain": domain, "vector": vector, "mode": mode, "scenario": scenario_id,
                "Td_s": "", "Tm_s": "", "Tu_s": "", "note": "ATTACK_START no encontrado en el log",
            })
            continue

        attack_starts = _filter(attack_starts_all, t_start, t_end)
        detections    = _filter(detections_all,    t_start, t_end)
        mitigations   = _filter(mitigations_all,   t_start, t_end)
        unblocks      = _filter(unblocks_all,      t_start, t_end)
        records = compute_stats(attack_starts, detections, mitigations, unblocks)
        records = [r for r in records if r["domain"] == domain]

        if not records:
            rows.append({
                "domain": domain, "vector": vector, "mode": mode, "scenario": scenario_id,
                "Td_s": "", "Tm_s": "", "Tu_s": "", "note": "sin mitigacion detectada en su ventana",
            })
            continue

        r0 = records[0]
        rows.append({
            "domain": domain, "vector": vector, "mode": mode, "scenario": scenario_id,
            "Td_s": r0["Td_s"], "Tm_s": r0["Tm_s"], "Tu_s": r0["Tu_s"], "note": "",
        })

    print(f"\n{'='*90}")
    print(f"{'MATRIZ DE 24 COMBINACIONES BASICAS':^90}")
    print(f"{'='*90}")
    print(f"  {'Dominio':<12}{'Vector':<8}{'Modo':<7}{'Td(s)':<10}{'Tm(s)':<10}{'Tu(s)':<10}Nota")
    for r in rows:
        print(f"  {r['domain']:<12}{r['vector']:<8}{r['mode']:<7}"
              f"{str(r['Td_s']):<10}{str(r['Tm_s']):<10}{str(r['Tu_s']):<10}{r['note']}")

    n_ok = sum(1 for r in rows if r["Td_s"] != "")
    print(f"\n  {n_ok}/{len(rows)} combinaciones con Td medido.")

    with open(args.csv, "w", newline="") as f:
        w = csv_module.DictWriter(f, fieldnames=["domain", "vector", "mode", "scenario", "Td_s", "Tm_s", "Tu_s", "note"])
        w.writeheader()
        w.writerows(rows)
    print(f"  CSV guardado: {args.csv}")

    return all_ok and n_ok == len(rows)


if __name__ == "__main__":
    ok = main()
    print(f"\n{'PASS' if ok else 'FAIL (ver notas arriba)'}")
    sys.exit(0 if ok else 1)
