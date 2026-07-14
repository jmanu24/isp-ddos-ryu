"""
webtool/orchestrator.py — single-process owner of the star topology's
Mininet net, the Ryu controller subprocess, and every live attack
(enterprise/mobile/broadband). Driven by webtool/app.py's Flask routes.

Single-process design: this process (not a child, no IPC) owns Mininet
directly, the same way simulation/ue_traffic_generator.py --interactive
already does -- attacks need to call host.popen(...) on live Mininet Node
objects, which aren't serializable across a process boundary without a
bespoke RPC layer this repo has no precedent for. The whole app needs
root regardless (Mininet, hping3, bngblaster, the BNG netns move), so
there's no privilege boundary worth preserving by splitting processes.

A single threading.RLock guards all state mutation -- reentrant so
stop_topology() can call stop_all_attacks() (and stop_attack() can be
invoked either from a Flask request thread or from an expired
threading.Timer, i.e. a different thread either way) without a same-
thread self-deadlock.
"""

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))

import config.settings as settings  # noqa: E402
from topologies.star_topology import (  # noqa: E402
    build_topology, add_central_server, _disable_rp_filter_star,
    attach_bng_gateway_to_r1, CENTRAL_SERVER_IP,
    ROLE_ENTERPRISE, ROLE_MOBILE_GNB, ROLE_FIXED,
)
from simulation.gnb_pool import GnbManager  # noqa: E402
from webtool import enterprise_ops  # noqa: E402
from webtool.bng_ops import BngLifecycle  # noqa: E402
from webtool.state import webtool_state  # noqa: E402

OFP_PORT = 6653
SETUP_BNG_NETNS_SCRIPT = REPO_DIR / "deploy" / "setup_bng_netns.sh"
UE_KPM_MONITOR_SCRIPT = REPO_DIR / "simulation" / "ue_kpm_monitor.py"
CONTROLLER_LOG_PATH = "/tmp/webtool_controller.log"

# UeSpec/enterprise_ops.hping3_argv both key protocol off these same
# strings ("UDP"/"TCP_SYN"/"ICMP") -- the web UI only ever exposes the
# 3 requirement-8 attack types, mapped here once for both domains.
ATTACK_TYPE_TO_PROTOCOL = {"SYN": "TCP_SYN", "UDP": "UDP", "ICMP": "ICMP"}
_BROADBAND_ATTACK_SCENARIO = {"SYN": "syn_flood", "UDP": "udp_flood", "ICMP": "icmp_flood"}


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def _find_ryu_manager() -> str:
    """
    This process needs BOTH mininet (only ever installed against the
    system python3 in this repo's own deploy scripts/docs -- every
    topology/simulation script here is launched with a plain `sudo
    python3 ...`, never through a venv) and Flask/ryu (installed inside
    ./venv per this repo's requirements.txt). Those two dependency sets
    don't coexist in one interpreter on a typical setup, so webtool/
    app.py itself is expected to run under the system python3 -- which
    means venv/bin isn't on PATH here, and a bare "ryu-manager" lookup
    fails even though the venv has it. Prefer the repo-relative
    venv/bin/ryu-manager (this repo's own convention) before falling
    back to PATH, so ryu-manager still runs under the venv's
    interpreter (where ryu/numpy/Flask are actually installed) without
    requiring the venv to be activated in webtool/app.py's own shell.
    """
    candidate = REPO_DIR / "venv" / "bin" / "ryu-manager"
    if candidate.exists():
        return str(candidate)
    return "ryu-manager"


class Orchestrator:

    def __init__(self):
        self._lock = threading.RLock()

        self.net = None
        self.r1 = None
        self.switches = None
        self.host_map: Dict[int, dict] = {}  # {i: {"enterprise":H,"mobile_gnb":H,"fixed":H}}

        self.controller_proc: Optional[subprocess.Popen] = None
        self._controller_log_fh = None

        self.gnb_manager: Optional[GnbManager] = None
        self.bng: Optional[BngLifecycle] = None
        self.monitor_proc = None
        self.enterprise_benign: Dict[int, object] = {}  # switch_index -> proc

        self.enterprise_procs: Dict[str, list] = {}  # attack_id -> [proc, ...]
        self._attack_domain: Dict[str, str] = {}      # attack_id -> domain
        self.attack_timers: Dict[str, threading.Timer] = {}
        self._active_broadband_attack: Optional[str] = None

    # ------------------------------------------------------------------
    # Controller lifecycle
    # ------------------------------------------------------------------

    def start_controller(self) -> dict:
        with self._lock:
            if _port_in_use(OFP_PORT):
                webtool_state.set_controller_status("running")
                webtool_state.add_event(
                    f"Puerto {OFP_PORT} ya en uso -- se asume un controlador existente"
                )
                return {"ok": True, "adopted": True}

            webtool_state.set_controller_status("starting")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(REPO_DIR)
            log_fh = open(CONTROLLER_LOG_PATH, "a")
            self.controller_proc = subprocess.Popen(
                [_find_ryu_manager(), "--observe-links", "controller/ryu_controller_2.py"],
                cwd=str(REPO_DIR), env=env, stdout=log_fh, stderr=subprocess.STDOUT,
            )
            self._controller_log_fh = log_fh

            for _ in range(50):
                if _port_in_use(OFP_PORT):
                    webtool_state.set_controller_status("running")
                    return {"ok": True}
                if self.controller_proc.poll() is not None:
                    webtool_state.set_controller_status("error")
                    return {"ok": False, "error": f"ryu-manager termino antes de tiempo, ver {CONTROLLER_LOG_PATH}"}
                time.sleep(0.1)

            webtool_state.set_controller_status("error")
            return {"ok": False, "error": f"timeout esperando bind en puerto {OFP_PORT}"}

    def stop_controller(self) -> dict:
        with self._lock:
            if self.controller_proc is None:
                webtool_state.set_controller_status("stopped")
                return {"ok": True, "note": "no fue iniciado por esta app (puede seguir corriendo si era externo)"}
            self.controller_proc.terminate()
            try:
                self.controller_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.controller_proc.kill()
            self.controller_proc = None
            if self._controller_log_fh is not None:
                self._controller_log_fh.close()
                self._controller_log_fh = None
            webtool_state.set_controller_status("stopped")
            return {"ok": True}

    # ------------------------------------------------------------------
    # Topology lifecycle
    # ------------------------------------------------------------------

    def start_topology(self) -> dict:
        with self._lock:
            if self.net is not None:
                return {"ok": True, "already_running": True}

            webtool_state.set_topology_status("starting")
            try:
                self.net, self.r1, self.switches, hosts = build_topology()
                add_central_server(self.r1)
                _disable_rp_filter_star(self.r1, len(self.switches))

                subprocess.run(["sudo", str(SETUP_BNG_NETNS_SCRIPT)], check=True)
                attach_bng_gateway_to_r1(self.r1)

                self.host_map = hosts

                gnb_hosts = {i: hosts[i][ROLE_MOBILE_GNB] for i in hosts}
                self.gnb_manager = GnbManager(gnb_hosts)
                self.gnb_manager.start_benign_baseline(CENTRAL_SERVER_IP)
                self.gnb_manager.start_rc_watch(tick=settings.COLLECT_INTERVAL)

                self.monitor_proc = self.r1.popen(
                    ["python3", str(UE_KPM_MONITOR_SCRIPT), "--tick", str(settings.COLLECT_INTERVAL)]
                )

                self.bng = BngLifecycle(target_ip=CENTRAL_SERVER_IP)
                self.bng.start_baseline()

                self.enterprise_benign = {
                    i: enterprise_ops.start_benign_loop(roles[ROLE_ENTERPRISE], CENTRAL_SERVER_IP)
                    for i, roles in hosts.items()
                }

                self._populate_nodes(hosts)

                webtool_state.set_topology_status("running")
                return {"ok": True}
            except Exception as exc:
                webtool_state.set_topology_status("error")
                webtool_state.add_event(f"Error al iniciar la topologia: {exc}")
                return {"ok": False, "error": str(exc)}

    def _populate_nodes(self, hosts: dict) -> None:
        nodes = {
            "r1": {"id": "r1", "domain": "core", "switch_index": None, "role": "router", "ip": None},
            "central_server": {
                "id": "central_server", "domain": "core", "switch_index": None,
                "role": "server", "ip": CENTRAL_SERVER_IP,
            },
        }
        role_domain = {ROLE_ENTERPRISE: "enterprise", ROLE_MOBILE_GNB: "mobile", ROLE_FIXED: "broadband"}
        for i, roles in hosts.items():
            for role_key, domain in role_domain.items():
                host = roles[role_key]
                nodes[host.name] = {
                    "id": host.name, "domain": domain, "switch_index": i,
                    "role": role_key, "ip": host.IP(),
                }
        webtool_state.set_nodes(nodes)

    def stop_topology(self) -> dict:
        with self._lock:
            self.stop_all_attacks()

            if self.gnb_manager is not None:
                self.gnb_manager.stop_all()
                self.gnb_manager = None
            if self.bng is not None:
                self.bng.stop_all()
                self.bng = None
            if self.monitor_proc is not None:
                enterprise_ops.stop_attack(self.monitor_proc)
                self.monitor_proc = None
            for proc in self.enterprise_benign.values():
                enterprise_ops.stop_attack(proc)
            self.enterprise_benign = {}

            if self.net is not None:
                self.net.stop()
            self.net = self.r1 = self.switches = None
            self.host_map = {}

            webtool_state.set_topology_status("stopped")
            webtool_state.set_nodes({})
            return {"ok": True}

    # ------------------------------------------------------------------
    # Attacks
    # ------------------------------------------------------------------

    def start_enterprise_attack(self, switch_indices: List[int], attack_type: str, dst_port: int,
                                 target_ip: str, duration: Optional[float] = None) -> dict:
        with self._lock:
            if self.net is None:
                return {"ok": False, "error": "la topologia no esta corriendo"}
            protocol = ATTACK_TYPE_TO_PROTOCOL[attack_type]
            attack_id = str(uuid4())
            procs = [
                enterprise_ops.start_attack(self.host_map[i][ROLE_ENTERPRISE], protocol, dst_port,
                                             target_ip, ["--flood"])
                for i in switch_indices
            ]
            self.enterprise_procs[attack_id] = procs
            self._attack_domain[attack_id] = "enterprise"
            webtool_state.add_attack(attack_id, {
                "domain": "enterprise", "switch_indices": switch_indices, "attack_type": attack_type,
                "target_ip": target_ip, "started_at": time.time(), "duration": duration,
            })
            self._schedule_auto_stop(attack_id, duration)
            return {"ok": True, "attack_id": attack_id}

    def start_mobile_attack(self, switch_indices: List[int], attack_type: str, dst_port: int,
                             target_ip: str, count_per_gnb: int = 1,
                             duration: Optional[float] = None) -> dict:
        with self._lock:
            if self.gnb_manager is None:
                return {"ok": False, "error": "la topologia no esta corriendo"}
            protocol = ATTACK_TYPE_TO_PROTOCOL[attack_type]
            attack_id = self.gnb_manager.start_attack(
                switch_indices=switch_indices, count_per_gnb=count_per_gnb, protocol=protocol,
                dst_port=dst_port, target_ip=target_ip, rate_flags=["--flood"],
            )
            self._attack_domain[attack_id] = "mobile"
            webtool_state.add_attack(attack_id, {
                "domain": "mobile", "switch_indices": switch_indices, "attack_type": attack_type,
                "target_ip": target_ip, "started_at": time.time(), "duration": duration,
            })
            self._schedule_auto_stop(attack_id, duration)
            return {"ok": True, "attack_id": attack_id}

    def start_broadband_attack(self, switch_indices: List[int], attack_type: str, target_ip: str,
                                duration: Optional[float] = None) -> dict:
        with self._lock:
            if self.bng is None:
                return {"ok": False, "error": "la topologia no esta corriendo"}
            scenario = _BROADBAND_ATTACK_SCENARIO.get(attack_type)
            if scenario is None:
                return {"ok": False, "error": f"tipo de ataque no soportado en broadband: {attack_type}"}
            if self._active_broadband_attack is not None:
                return {"ok": False, "error": "ya hay un ataque broadband activo -- detenlo primero"}

            self.bng.target_ip = target_ip
            self.bng.start_attack(scenario)

            attack_id = str(uuid4())
            self._attack_domain[attack_id] = "broadband"
            self._active_broadband_attack = attack_id
            webtool_state.add_attack(attack_id, {
                "domain": "broadband", "switch_indices": switch_indices, "attack_type": attack_type,
                "target_ip": target_ip, "started_at": time.time(), "duration": duration,
            })
            self._schedule_auto_stop(attack_id, duration)
            return {"ok": True, "attack_id": attack_id}

    def stop_attack(self, attack_id: str) -> dict:
        with self._lock:
            domain = self._attack_domain.pop(attack_id, None)
            if domain is None:
                return {"ok": False, "error": "attack_id desconocido"}
            self._cancel_timer(attack_id)

            if domain == "enterprise":
                for proc in self.enterprise_procs.pop(attack_id, []):
                    enterprise_ops.stop_attack(proc)
            elif domain == "mobile":
                if self.gnb_manager is not None:
                    self.gnb_manager.stop_attack(attack_id)
            elif domain == "broadband":
                if self.bng is not None:
                    self.bng.stop_attack()
                self._active_broadband_attack = None

            webtool_state.remove_attack(attack_id)
            return {"ok": True}

    def stop_all_attacks(self) -> dict:
        with self._lock:
            for attack_id in list(self._attack_domain.keys()):
                self.stop_attack(attack_id)
            return {"ok": True}

    def _cancel_timer(self, attack_id: str) -> None:
        timer = self.attack_timers.pop(attack_id, None)
        if timer is not None:
            timer.cancel()

    def _schedule_auto_stop(self, attack_id: str, duration: Optional[float]) -> None:
        if not duration:
            return
        timer = threading.Timer(duration, self.stop_attack, args=[attack_id])
        timer.daemon = True
        self.attack_timers[attack_id] = timer
        timer.start()

    # ------------------------------------------------------------------

    def central_server_ip(self) -> str:
        return CENTRAL_SERVER_IP

    def valid_targets(self) -> List[str]:
        with self._lock:
            return [host.IP() for roles in self.host_map.values() for host in roles.values()]
