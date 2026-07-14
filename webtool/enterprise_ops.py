"""
webtool/enterprise_ops.py — real (unspoofed) hping3 attack/benign helpers
for the star topology's ent_<i> hosts.

Unlike simulation/gnb_pool.py's mobile UEs, an enterprise host attacking
is just itself -- no spoofed source, no separate identity to track. Real,
unspoofed traffic from a real Mininet host is already exactly what the
native OpenFlow "enterprise" detection pipeline (telemetry/
openflow_adapter.py) handles with zero simulation layer needed, so this
module is a thin process-lifecycle wrapper, not a scenario engine.
"""

import subprocess
from typing import List


def hping3_argv(protocol: str, dst_port: int, target_ip: str, rate_flags: List[str]) -> List[str]:
    """Same shape as simulation/ue_traffic_generator.py's _hping3_argv,
    minus the -a spoofing flag -- an enterprise host attacks as itself."""
    argv = ["hping3"]
    if protocol == "UDP":
        argv += ["--udp", "-p", str(dst_port), "--keep"]
    elif protocol == "TCP_SYN":
        argv += ["-S", "-p", str(dst_port), "--keep"]
    elif protocol == "ICMP":
        argv += ["--icmp"]
    argv += list(rate_flags)
    argv.append(target_ip)
    return argv


def start_attack(host, protocol: str, dst_port: int, target_ip: str, rate_flags: List[str]):
    argv = hping3_argv(protocol, dst_port, target_ip, rate_flags)
    return host.popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_attack(proc) -> None:
    """Doubles as a generic process-teardown helper for this module's
    callers (webtool/orchestrator.py also uses it for ue_kpm_monitor.py's
    and the enterprise benign loops' processes -- same terminate/kill
    fallback either way)."""
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


# On/off ICMP burst loop, same shape as simulation/ue_traffic_generator.py's
# _BENIGN_LOOP_TEMPLATE minus the -a spoofing flag.
_BENIGN_LOOP_TEMPLATE = (
    "while true; do "
    "hping3 --icmp -c $((RANDOM % 5 + 3)) -i u200000 {target} >/dev/null 2>&1; "
    "sleep $((RANDOM % 8 + 4)); "
    "done"
)


def benign_loop_argv(target_ip: str) -> List[str]:
    return ["bash", "-c", _BENIGN_LOOP_TEMPLATE.format(target=target_ip)]


def start_benign_loop(host, target_ip: str):
    return host.popen(benign_loop_argv(target_ip), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
