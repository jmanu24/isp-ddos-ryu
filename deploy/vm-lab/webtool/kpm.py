"""
webtool/kpm.py -- polls the KPM bridge xApp (kpm_bridge_xapp.py, exposed
on ric:8767/kpm inside the python_xapp_runner container -- see
mobile-bringup-order / oran-sc-ric-migration memories) and tails the
actuator/xApp container logs for DETECTION/MITIGATION lines, the same
homologated log format webtool/state.py's own docstring documents for
the mininet lab.
"""

import json
from typing import List

from webtool.ssh_ops import run

RIC_NODE = "ric"
KPM_CONTAINER = "python_xapp_runner"
ACTUATOR_CONTAINER = "rc_actuator_runner"  # deploy/vm-lab commit 2a9c923: its own container


def poll_kpm_samples() -> List[dict]:
    res = run(RIC_NODE, f"docker exec {KPM_CONTAINER} curl -s --max-time 3 http://localhost:8767/kpm", timeout=8, become=True)
    if not res.ok or not res.stdout.strip():
        return []
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return data.get("samples", data.get("du_nodes", [])) if isinstance(data.get("samples", data.get("du_nodes")), list) else [data]
    if isinstance(data, list):
        return data
    return []


def tail_mitigation_events(since_marker: str = None, lines: int = 100) -> List[str]:
    """Tails the actuator container's own log for lines that look like a
    detection/mitigation decision -- grep instead of full JSON parsing
    since the exact log schema isn't guaranteed stable across the RC
    actuator revisions this lab has gone through (see
    oran-sc-ric-migration memory)."""
    res = run(
        RIC_NODE,
        f"docker logs --tail {int(lines)} {ACTUATOR_CONTAINER} 2>&1 "
        f"| grep -iE 'detect|mitigat|block|threshold|ddos' || true",
        timeout=10, become=True,
    )
    if not res.ok:
        return []
    return [l for l in res.stdout.splitlines() if l.strip()]
