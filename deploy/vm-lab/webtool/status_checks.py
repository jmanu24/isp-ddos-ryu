"""
webtool/status_checks.py -- per-role liveness/signal probes, one SSH
round trip per VM per poll cycle. Mirrors the exact validation signals
documented in the mobile-bringup-order memory (E2/F1/RRC/NGAP via each
component's OWN log, never e2mgr's connectionStatus, which is
frequently stale) so the dashboard agrees with what bring-up already
proved reliable.

`reachable` always means "the SSH transport itself worked" (SshResult's
own .reachable, rc not in {255,124,127}) -- NEVER a remote command's exit
status (e.g. `systemctl is-active` on a dead service legitimately exits
non-zero over a perfectly healthy SSH session). Every probe below keeps
those two concepts separate.
"""

from typing import Dict

from webtool.inventory import NODES, UE_NETNS
from webtool.ssh_ops import run

_TIMEOUT = 8


def _probe_generic(node_name: str) -> Dict:
    res = run(node_name, "echo up", timeout=_TIMEOUT)
    return {"reachable": res.reachable}


_ROLE_PROBES = {}


def _register(role):
    def deco(fn):
        _ROLE_PROBES[role] = fn
        return fn
    return deco


@_register("core5g_open5gs")
def _probe_core5g(node_name: str) -> Dict:
    res = run(node_name, "sudo docker ps --format '{{.Names}}: {{.Status}}' 2>&1", timeout=_TIMEOUT)
    healthy = res.ok and "open5gs_5gc" in res.stdout and "Up" in res.stdout
    return {"reachable": res.reachable, "open5gs_container": res.stdout.strip() if res.ok else res.stderr, "healthy": healthy}


@_register("ric_flexric")
def _probe_ric(node_name: str) -> Dict:
    res = run(node_name, "sudo docker ps --format '{{.Names}}' 2>&1 | wc -l", timeout=_TIMEOUT)
    n_containers = int(res.stdout.strip()) if res.ok and res.stdout.strip().isdigit() else 0
    bridge = run(node_name, "sudo docker exec python_xapp_runner curl -s --max-time 3 http://localhost:8767/kpm 2>&1 | head -c 200", timeout=_TIMEOUT)
    return {
        "reachable": res.reachable,
        "containers_up": n_containers,
        "healthy": n_containers >= 7,
        "kpm_bridge_responding": bridge.ok and bool(bridge.stdout.strip()) and "Failed to connect" not in bridge.stdout,
    }


@_register("ran_srsran")
def _probe_cu(node_name: str) -> Dict:
    alive = run(node_name, "pgrep -f '^srscu -c' >/dev/null && echo yes || echo no", timeout=_TIMEOUT)
    # NOT `grep -c ... || echo 0` -- grep -c exits 1 on zero matches even
    # though it already printed "0", so `||` fires too and doubles the
    # line ("0\n0"), which `not in ("", "0")` then misreads as truthy.
    # `; true` keeps grep's own stdout (0 or N) as the only output.
    e2 = run(node_name, "grep -c 'E2 Setup procedure successful' /tmp/cu.log 2>/dev/null; true", timeout=_TIMEOUT)
    return {
        "reachable": alive.reachable,
        "srscu_alive": alive.stdout.strip() == "yes",
        "e2_setup_ok": e2.stdout.strip() not in ("", "0"),
    }


@_register("du_srsran")
def _probe_du(node_name: str) -> Dict:
    alive = run(node_name, "pgrep -f '^srsdu -c' >/dev/null && echo yes || echo no", timeout=_TIMEOUT)
    # NOT `grep -c ... || echo 0` -- see _probe_cu's own comment: grep -c
    # exits 1 on zero matches despite printing "0", so `||` double-prints.
    log = run(node_name, "grep -c 'E2 Setup procedure successful' /tmp/du.log 2>/dev/null; true", timeout=_TIMEOUT)
    # bring_up_du.yml truncates /tmp/du.log on every relaunch, but reading
    # the LAST matching line (not just a raw count) is still more robust
    # against a manual/out-of-band restart that didn't go through it.
    last_events = run(
        node_name,
        "grep -n 'F1 Setup Failure\\|F1 Setup Response' /tmp/du.log 2>/dev/null | tail -1; true",
        timeout=_TIMEOUT,
    )
    f1_currently_failed = "F1 Setup Failure" in last_events.stdout
    return {
        "reachable": alive.reachable,
        "srsdu_alive": alive.stdout.strip() == "yes",
        "e2_setup_ok": log.stdout.strip() not in ("", "0"),
        "f1_setup_failed": f1_currently_failed,
    }


@_register("ue_srsue")
def _probe_ue_host(node_name: str) -> Dict:
    netns_here = [u for u in UE_NETNS if u.host == node_name]
    per_ue = {}
    reachable = True
    for u in netns_here:
        active = run(node_name, f"systemctl is-active {u.netns} 2>&1", timeout=_TIMEOUT)
        ip = run(node_name, f"ip netns exec {u.netns} ip -4 -o addr show tun_srsue 2>/dev/null | awk '{{print $4}}' | cut -d/ -f1", timeout=_TIMEOUT, become=True)
        reachable = reachable and active.reachable
        per_ue[u.netns] = {"service_active": active.stdout.strip(), "ip": ip.stdout.strip() if ip.ok else None}
    return {"reachable": reachable, "ues": per_ue}


@_register("bng")
def _probe_bng(node_name: str) -> Dict:
    res = run(node_name, "systemctl is-active accel-ppp 2>&1", timeout=_TIMEOUT)
    return {"reachable": res.reachable, "accel_ppp_active": res.stdout.strip()}


@_register("suscriptor")
def _probe_suscriptor(node_name: str) -> Dict:
    res = run(node_name, "ip -o link show 2>/dev/null | grep -c macvlan; true", timeout=_TIMEOUT)
    return {"reachable": res.reachable, "macvlan_subs": res.stdout.strip()}


@_register("br")
def _probe_br(node_name: str) -> Dict:
    res = run(node_name, "systemctl is-active bgpd 2>&1 || systemctl is-active frr 2>&1", timeout=_TIMEOUT)
    return {"reachable": res.reachable, "bgpd_active": res.stdout.strip()}


@_register("peer_router")
def _probe_peer_router(node_name: str) -> Dict:
    res = run(node_name, "systemctl is-active bird 2>&1", timeout=_TIMEOUT)
    return {"reachable": res.reachable, "bird_active": res.stdout.strip()}


@_register("pe_ovs")
def _probe_pe(node_name: str) -> Dict:
    res = run(node_name, "ovs-vsctl show 2>&1 | head -c 500", timeout=_TIMEOUT, become=True)
    return {"reachable": res.reachable, "ovs_ok": res.ok}


@_register("victim")
def _probe_victim(node_name: str) -> Dict:
    res = run(node_name, "pgrep -f 'python3' >/dev/null && echo yes || echo no", timeout=_TIMEOUT)
    return {"reachable": res.reachable, "service_running": res.stdout.strip() == "yes"}


@_register("enterprise_site")
def _probe_enterprise(node_name: str) -> Dict:
    return _probe_generic(node_name)


@_register("orchestrator")
def _probe_orchestrator(node_name: str) -> Dict:
    res = run(node_name, "systemctl is-active ryu-manager 2>&1", timeout=_TIMEOUT)
    return {"reachable": res.reachable, "ryu_manager_active": res.stdout.strip()}


def probe_node(node_name: str, role: str) -> Dict:
    fn = _ROLE_PROBES.get(role, _probe_generic)
    try:
        return fn(node_name)
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "error": str(exc)}


def probe_all() -> Dict[str, Dict]:
    return {n.name: probe_node(n.name, n.role) for n in NODES}
