#!/usr/bin/env python3
"""
BGP Peering domain validation harness -- confirms the mechanism
documented in docs/peering-plan.md §2/§5: an announced BGP FlowSpec
discard route gets installed as a REAL nftables rule inside r1's own
namespace by `flow` (github.com/hack3ric/flow, reached over exabgp --
see mitigation/peering_backend.py's docstring for why FRR is NOT used
here, FRRouting/frr#3160), and that withdrawing it removes the rule.

Deliberately standalone (not part of the shipped webtool), matching
validate_phase1.py's own throwaway-but-useful harness convention --
r1's Mininet node/namespace only stays alive as long as this script's
own process does, so announce/verify/withdraw/verify all happen inside
one process, ending with an explicit net.stop() teardown.

Prerequisites:
  - deploy/install_bgp_peering.sh already run (installs flow, exabgp, nftables).

Usage:
  sudo python3 validate_peering.py
"""
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_DIR))

import config.settings as settings  # noqa: E402
from topologies.star_topology import (  # noqa: E402
    build_topology, add_central_server, _disable_rp_filter_star,
    attach_external_peer, R1_EXTERNAL_IP, EXTERNAL_PEER_IP,
)
from webtool.peering_ops import (  # noqa: E402
    PeeringLifecycle, FLOW_LOG_PATH, EXABGP_LOG_PATH, NFCAPD_ROTATE_SECONDS,
)
from collectors.peering_flow_collector import PeeringFlowCollector  # noqa: E402

TEST_DST = "198.51.100.99"  # TEST-NET-2 (RFC 5737) -- never a real host
FIFO = "/run/exabgp/exabgp.in"


def check(label: str, ok: bool) -> bool:
    print(f"  [{'OK' if ok else 'FALLO'}] {label}")
    return ok


def _flow_command(verb: str) -> str:
    return (
        f"{verb} flow route {{ match {{ destination {TEST_DST}/32; "
        f"protocol tcp; destination-port =80; }} then {{ discard; }} }}"
    )


def main() -> bool:
    all_ok = True

    print("=== 1. Construyendo topologia en estrella ===")
    net, r1, switches, hosts = build_topology()
    add_central_server(r1)
    _disable_rp_filter_star(r1, len(switches))
    peer_ext = attach_external_peer(net, r1)

    print("\n=== 2. Arrancando flow (en r1) + exabgp (namespace raiz) + softflowd/nfcapd ===")
    peering = PeeringLifecycle(r1)
    try:
        peering.start()
        all_ok &= check("PeeringLifecycle.start() no lanzo excepcion", True)
    except Exception as exc:
        check("PeeringLifecycle.start() no lanzo excepcion", False)
        print(f"    excepcion: {exc!r}")
        # A failure partway through start() (e.g. a rejected softflowd
        # flag) can still leave earlier processes running -- exabgp in
        # particular is a plain root-namespace subprocess.Popen, not
        # something net.stop() would ever reach on its own.
        peering.stop()
        net.stop()
        return False

    # Constructed here, before any of this run's own traffic exists --
    # PeeringFlowCollector seeds _processed_files with whatever's
    # already on disk at construction time (deliberately, so a fresh
    # controller start doesn't replay hours-old capture files as live
    # traffic -- see docs/peering-plan.md §2.3). Building it any later
    # (e.g. right before the final poll(), after our own flood's file
    # has already rotated) would seed it with OUR OWN real data too,
    # marking it "already seen" before poll() ever gets a chance to
    # return it. Confirmed on the VM: constructing it late made a real,
    # successful flood test report zero records.
    collector = PeeringFlowCollector()

    print("\n=== 3. Esperando sesion BGP exabgp<->flow ===")
    time.sleep(6)
    flow_log = Path(FLOW_LOG_PATH).read_text()
    established = "established" in flow_log
    all_ok &= check("sesion BGP establecida (ver flow log)", established)
    if not established:
        print(f"    flow log:\n{flow_log}")
        print(f"    exabgp log:\n{Path(EXABGP_LOG_PATH).read_text()}")

    if established:
        print(f"\n=== 4. Anunciando ruta FlowSpec de descarte para {TEST_DST}:80/tcp ===")
        Path(FIFO).write_text(_flow_command("announce") + "\n")
        time.sleep(2)
        after_announce = r1.cmd("nft list ruleset")
        all_ok &= check(
            f"regla real en nftables (dentro de r1) para {TEST_DST}",
            TEST_DST in after_announce,
        )

        print("\n=== 5. Retirando la ruta ===")
        Path(FIFO).write_text(_flow_command("withdraw") + "\n")
        time.sleep(2)
        after_withdraw = r1.cmd("nft list ruleset")
        all_ok &= check(
            f"regla removida de nftables tras el withdraw",
            TEST_DST not in after_withdraw,
        )

    print(f"\n=== 6. Telemetria real: flood ICMP desde peer_ext ({EXTERNAL_PEER_IP}) hacia r1 ===")
    print(f"    peer_ext-eth0: {peer_ext.cmd('ip addr show peer_ext-eth0')}")
    # A real ping (a handful of packets) never fills softflowd's pcap
    # capture ring on Linux (see webtool/peering_ops.py's softflowd
    # invocation comment for why), so it never gets past libpcap into
    # softflowd's own processing -- confirmed on the VM via softflowctl
    # statistics showing 0 packets processed despite a successful ping.
    # A short hping3 flood (same tool/pattern webtool/orchestrator.py
    # already uses for attack scenarios) generates enough volume to
    # flush promptly, and is what this pipeline actually exists to
    # observe.
    flood_proc = peer_ext.popen(
        ["hping3", "--icmp", "--flood", R1_EXTERNAL_IP],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    flood_proc.terminate()
    try:
        flood_proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        flood_proc.kill()
    all_ok &= check("flood ICMP peer_ext -> r1 ejecutado (2s)", True)

    # DIAGNOSTIC (temporary): a real run showed the flood's data file only
    # getting its permanent nfcapd.<timestamp> name at peering.stop()'s
    # SIGTERM-triggered final flush, well after this wait+poll() already
    # ran and found nothing -- meaning nfcapd wasn't performing a natural,
    # timed rotation within NFCAPD_ROTATE_SECONDS+3s at all. Waiting much
    # longer here, and dumping the directory state right before poll(),
    # to see directly how long a real rotation actually takes from a
    # clean nfcapd start (removing the SIGTERM-flush confound entirely).
    wait_s = NFCAPD_ROTATE_SECONDS * 4 + 5
    print(f"    esperando {wait_s}s (diagnostico: bastante mas que "
          f"NFCAPD_ROTATE_SECONDS+3) a que nfcapd rote un archivo de captura...")
    time.sleep(wait_s)

    print(f"    estado de {settings.PEERING_NFCAPD_DIR} justo antes de poll():")
    for fname in sorted(os.listdir(settings.PEERING_NFCAPD_DIR)):
        print(f"      {fname}")

    records = collector.poll()
    saw_traffic = any(r["src_ip"] == EXTERNAL_PEER_IP or r["dst_ip"] == EXTERNAL_PEER_IP for r in records)
    all_ok &= check(
        f"collectors/peering_flow_collector.py vio trafico real de {EXTERNAL_PEER_IP} "
        f"(via softflowd -> nfcapd -> nfdump)",
        saw_traffic,
    )
    if not saw_traffic:
        print(f"    registros vistos por el collector: {records}")

    print("\n=== 7. Apagando (peering.stop() + net.stop()) ===")
    peering.stop()
    net.stop()
    check("teardown completado", True)

    return all_ok


if __name__ == "__main__":
    ok = main()
    print(f"\n{'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
