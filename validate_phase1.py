#!/usr/bin/env python3
"""
Throwaway Phase 1 validation harness -- NOT part of the shipped webtool,
safe to delete after use. Confirms topologies/star_topology.py +
simulation/gnb_pool.py work end-to-end (star topology, central server
reachability, r1-as-BNG-gateway netns move, gNB benign baseline, a real
UDP-flood attack) before Phase 2 (the web backend) gets built on top.

Prerequisites:
  - Controller running in another terminal: sudo ./deploy/start_controller_pinned.sh
  - BNG veth pair already created: sudo ./deploy/setup_bng_netns.sh

Usage:
  sudo python3 validate_phase1.py
"""
import subprocess
import sys
import time
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_DIR))

from topologies.star_topology import (  # noqa: E402
    build_topology, add_central_server, _disable_rp_filter_star,
    attach_bng_gateway_to_r1, CENTRAL_SERVER_IP,
)
from simulation.gnb_pool import GnbManager  # noqa: E402
from simulation.bng_traffic_simulator import BngScenarioSession  # noqa: E402


def check(label: str, ok: bool) -> None:
    print(f"  [{'OK' if ok else 'FALLO'}] {label}")


def main():
    print("=== 1. Construyendo topologia en estrella ===")
    net, r1, switches, hosts = build_topology()
    add_central_server(r1)
    _disable_rp_filter_star(r1, len(switches))

    print("\n=== 2. Conectividad basica (los 12 hosts -> servidor central) ===")
    for i in sorted(hosts):
        for role, h in hosts[i].items():
            result = h.cmd(f'ping -c1 -W1 {CENTRAL_SERVER_IP}')
            check(f"{h.name} ({role}) -> {CENTRAL_SERVER_IP}",
                  "1 received" in result or "1 packets received" in result)

    print("\n=== 3. r1 como gateway de BNGBlaster (mover veth-n-peer a su netns) ===")
    attach_bng_gateway_to_r1(r1)
    inside = r1.cmd('ip addr show veth-n-peer')
    check("veth-n-peer visible dentro de r1 con 10.50.0.1/24", "10.50.0.1" in inside)
    root_check = subprocess.run(['ip', 'addr', 'show', 'veth-n-peer'], capture_output=True, text=True)
    check("veth-n-peer YA NO existe en el namespace raiz", root_check.returncode != 0)

    print("\n=== 4. Lanzando bngblaster real (escenario syn_flood) ===")
    bng = BngScenarioSession(scenario="syn_flood", target_ip=CENTRAL_SERVER_IP)
    bng.start()
    time.sleep(3)
    ping_result = r1.cmd('ping -c3 -W1 10.50.0.10')
    check("r1 -> bngblaster (10.50.0.10) responde", "0% packet loss" in ping_result)
    print(ping_result)

    print("\n=== 5. Lanzando ue_kpm_monitor.py en r1 (mide trafico UE real via nft) ===")
    monitor_proc = r1.popen(["python3", str(REPO_DIR / "simulation" / "ue_kpm_monitor.py")])
    time.sleep(2)

    print("\n=== 6. Pool de gNB: baseline benigno (4 UEs, una por gNB) ===")
    gnb_hosts = {i: hosts[i]["mobile_gnb"] for i in hosts}
    mgr = GnbManager(gnb_hosts)
    mgr.start_benign_baseline(CENTRAL_SERVER_IP)
    print("  Baseline iniciado. En otra terminal puedes revisar contadores nft:")
    print(f"    sudo mnexec -a $(pgrep -f 'mininet:r1' | head -1) nft -j list table inet ue_acct")

    print("\n=== 7. Ataque de prueba: gNB del switch 2 -> ent_1 (UDP flood) ===")
    target = hosts[1]["enterprise"].IP()
    attack_id = mgr.start_attack(
        switch_indices=[2], count_per_gnb=1, protocol="UDP", dst_port=0,
        target_ip=target, rate_flags=["--flood"],
    )
    print(f"  attack_id={attack_id}, objetivo={target}")
    print("  Revisa AHORA el log del controlador -- deberia aparecer:")
    print("    [mobile] DETECTION: ATTACK_DETECTED UDP_FLOOD ...")
    print("    [mobile] MITIGATION: THROTTLE UDP_FLOOD ...")

    input("\nPresiona Enter cuando hayas confirmado la deteccion/mitigacion arriba...")

    print("\n=== 8. Limpiando ===")
    mgr.stop_attack(attack_id)
    mgr.stop_all()
    bng.stop()
    monitor_proc.terminate()

    print("\n=== Entrando a la CLI de Mininet para inspeccion manual (Ctrl-D para salir y terminar) ===")
    from mininet.cli import CLI
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
