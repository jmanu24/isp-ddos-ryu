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
import sys
import time
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_DIR))

from topologies.star_topology import (  # noqa: E402
    build_topology, add_central_server, _disable_rp_filter_star,
)
from webtool.peering_ops import (  # noqa: E402
    PeeringLifecycle, FLOW_LOG_PATH, EXABGP_LOG_PATH,
)

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

    print("\n=== 2. Arrancando flow (en r1) + exabgp (namespace raiz) ===")
    peering = PeeringLifecycle(r1)
    try:
        peering.start()
        all_ok &= check("PeeringLifecycle.start() no lanzo excepcion", True)
    except Exception as exc:
        check("PeeringLifecycle.start() no lanzo excepcion", False)
        print(f"    excepcion: {exc!r}")
        net.stop()
        return False

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

    print("\n=== 6. Apagando (peering.stop() + net.stop()) ===")
    peering.stop()
    net.stop()
    check("teardown completado", True)

    return all_ok


if __name__ == "__main__":
    ok = main()
    print(f"\n{'PASS' if ok else 'FAIL'}")
    sys.exit(0 if ok else 1)
