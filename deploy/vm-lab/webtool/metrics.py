"""
webtool/metrics.py -- per-VM CPU%, mem% and per-interface throughput,
sampled over SSH with plain /proc reads (no agent to install on any of
the 16 VMs). CPU/throughput both need two samples a fixed interval
apart, so each call here takes 2 sightly-cheap SSH round trips ~1s apart
per node -- acceptable at the dashboard's own ~10s poll cadence, run in
parallel across nodes by the caller (app.py's polling loop), not here.
"""

import time
from typing import Dict, Optional

from webtool.ssh_ops import run

_CPU_CMD = "cat /proc/stat | head -1"
_MEM_CMD = "cat /proc/meminfo | head -3"
_NET_CMD = "cat /proc/net/dev"


def _parse_cpu_line(line: str) -> Optional[int]:
    # "cpu  user nice system idle iowait irq softirq steal ..."
    parts = line.split()
    if not parts or parts[0] != "cpu":
        return None
    return sum(int(x) for x in parts[1:])


def _parse_cpu_idle(line: str) -> Optional[int]:
    parts = line.split()
    if not parts or parts[0] != "cpu":
        return None
    return int(parts[4])  # idle field


def _parse_mem(text: str) -> Optional[float]:
    total = avail = None
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            total = int(line.split()[1])
        elif line.startswith("MemAvailable:"):
            avail = int(line.split()[1])
    if total and avail is not None:
        return round((1 - avail / total) * 100, 1)
    return None


def _parse_net(text: str) -> Dict[str, Dict[str, int]]:
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        iface, rest = line.split(":", 1)
        iface = iface.strip()
        if iface in ("lo",):
            continue
        fields = rest.split()
        if len(fields) < 16:
            continue
        out[iface] = {"rx_bytes": int(fields[0]), "tx_bytes": int(fields[8])}
    return out


def sample_node(node_name: str) -> Optional[Dict]:
    cpu1 = run(node_name, _CPU_CMD, timeout=6)
    net1 = run(node_name, _NET_CMD, timeout=6)
    if not (cpu1.ok and net1.ok):
        return None
    t1 = time.time()
    time.sleep(0.6)
    cpu2 = run(node_name, _CPU_CMD, timeout=6)
    mem = run(node_name, _MEM_CMD, timeout=6)
    net2 = run(node_name, _NET_CMD, timeout=6)
    t2 = time.time()
    if not (cpu2.ok and net2.ok):
        return None

    dt = max(t2 - t1, 0.1)
    cpu_pct = None
    total1, idle1 = _parse_cpu_line(cpu1.stdout), _parse_cpu_idle(cpu1.stdout)
    total2, idle2 = _parse_cpu_line(cpu2.stdout), _parse_cpu_idle(cpu2.stdout)
    if None not in (total1, idle1, total2, idle2) and total2 > total1:
        busy = (total2 - total1) - (idle2 - idle1)
        cpu_pct = round(100.0 * busy / (total2 - total1), 1)

    mem_pct = _parse_mem(mem.stdout) if mem.ok else None

    ifaces1, ifaces2 = _parse_net(net1.stdout), _parse_net(net2.stdout)
    iface_rates = {}
    for name, c2 in ifaces2.items():
        c1 = ifaces1.get(name)
        if not c1:
            continue
        rx_bps = max(0, c2["rx_bytes"] - c1["rx_bytes"]) * 8 / dt
        tx_bps = max(0, c2["tx_bytes"] - c1["tx_bytes"]) * 8 / dt
        iface_rates[name] = {"rx_bps": round(rx_bps), "tx_bps": round(tx_bps)}

    return {"t": t2, "cpu_pct": cpu_pct, "mem_pct": mem_pct, "iface": iface_rates}
