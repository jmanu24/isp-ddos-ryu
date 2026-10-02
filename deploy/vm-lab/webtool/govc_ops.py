"""
webtool/govc_ops.py -- govc wrapper for VM power state/on/off, sourcing
the lab's own ../.govc.env (never read its contents into Python -- always
shelled out to `. .govc.env` so the credentials never touch this
process's memory/logs as parsed values).
"""

import subprocess
import shlex
from pathlib import Path
from typing import Dict, List
from . import workstation_ops

VM_LAB_DIR = Path(__file__).resolve().parent.parent
GOVC_ENV = VM_LAB_DIR / ".govc.env"


def _govc(args: List[str], timeout: int = 20) -> subprocess.CompletedProcess:
    cmd = f"set -a; . {shlex.quote(str(GOVC_ENV))}; set +a; govc {' '.join(shlex.quote(a) for a in args)}"
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=timeout)


def power_states() -> Dict[str, str]:
    """Returns {vm_name: 'poweredOn'|'poweredOff'|'unknown'} for every VM
    govc can see. A single `govc find` + `govc object.collect` round trip
    would be faster, but `govc ls -l` output is stable/simple enough to
    parse and this is only polled every few seconds, not per-request."""
    if not GOVC_ENV.exists():
        return workstation_ops.states()
    try:
        proc = _govc(["vm.info", "-json", "*"])
    except (OSError, subprocess.TimeoutExpired):
        return workstation_ops.states()
    if proc.returncode != 0:
        return workstation_ops.states()
    import json
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return workstation_ops.states()
    states = {}
    for vm in data.get("virtualMachines", []) or []:
        name = vm.get("config", {}).get("name") or vm.get("name")
        summary = vm.get("summary", {}) or {}
        power = (summary.get("runtime", {}) or {}).get("powerState", "unknown")
        if name:
            states[name] = power
    states.update(workstation_ops.states())
    return states


def power(vm_name: str, on: bool) -> bool:
    if workstation_ops.owns(vm_name):
        return workstation_ops.power(vm_name, "on" if on else "off")
    proc = _govc(["vm.power", "-on" if on else "-off", vm_name], timeout=30)
    return proc.returncode == 0


def power_off_clean(vm_name: str) -> bool:
    """Graceful shutdown (govc vm.power -s), falling back to hard -off on
    the caller's own retry -- mirrors the manual method in
    mobile-bringup-order memory."""
    if workstation_ops.owns(vm_name):
        return workstation_ops.power(vm_name, "shutdown")
    proc = _govc(["vm.power", "-s", vm_name], timeout=30)
    return proc.returncode == 0
