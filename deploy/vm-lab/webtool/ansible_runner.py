"""
webtool/ansible_runner.py -- runs ansible-playbook as a subprocess (the
user's explicit choice: reuse reconnect_mobile_domain.yml as-is rather
than re-implementing its logic over raw SSH), streaming stdout line by
line into webtool_state so the UI can show a live console. Only one job
at a time -- the playbook itself is strictly sequential and power-cycles
shared VMs, so overlapping runs would race.
"""

import subprocess
import threading
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from webtool.state import vmlab_state

VM_LAB_DIR = Path(__file__).resolve().parent.parent
ANSIBLE_DIR = VM_LAB_DIR / "ansible"
RECONNECT_PLAYBOOK = "playbooks/reconnect_mobile_domain.yml"

_job_lock = threading.Lock()
_current_proc: Optional[subprocess.Popen] = None


def is_running() -> bool:
    job = vmlab_state.ansible_job
    return bool(job and job.get("running"))


def run_playbook(playbook: str, label: str, tags: Optional[List[str]] = None,
                  skip_tags: Optional[List[str]] = None,
                  extra_vars: Optional[dict] = None,
                  limit: Optional[str] = None) -> dict:
    global _current_proc
    if not _job_lock.acquire(blocking=False):
        return {"ok": False, "error": "ya hay un job de Ansible corriendo"}
    try:
        if is_running():
            _job_lock.release()
            return {"ok": False, "error": "ya hay un job de Ansible corriendo"}

        job_id = str(uuid4())
        argv = ["ansible-playbook", playbook]
        if tags:
            argv += ["--tags", ",".join(tags)]
        if skip_tags:
            argv += ["--skip-tags", ",".join(skip_tags)]
        if limit:
            argv += ["--limit", limit]
        for k, v in (extra_vars or {}).items():
            argv += ["-e", f"{k}={v}"]

        vmlab_state.set_ansible_job({"id": job_id, "label": label, "running": True, "lines": [], "rc": None})
        vmlab_state.add_event(f"ANSIBLE_START: {label} ({' '.join(argv)})")

        def _stream():
            global _current_proc
            try:
                proc = subprocess.Popen(
                    argv, cwd=str(ANSIBLE_DIR),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                )
                _current_proc = proc
                for line in proc.stdout:
                    vmlab_state.append_ansible_line(line.rstrip("\n"))
                proc.wait()
                rc = proc.returncode
            except Exception as exc:  # noqa: BLE001
                vmlab_state.append_ansible_line(f"[webtool] error lanzando ansible-playbook: {exc}")
                rc = -1
            finally:
                _current_proc = None
                job = vmlab_state.ansible_job or {}
                job.update({"running": False, "rc": rc})
                vmlab_state.set_ansible_job(job)
                vmlab_state.add_event(f"ANSIBLE_DONE: {label} rc={rc}")
                _job_lock.release()

        threading.Thread(target=_stream, daemon=True).start()
        return {"ok": True, "job_id": job_id}
    except Exception:
        _job_lock.release()
        raise


def cancel_current() -> dict:
    global _current_proc
    if _current_proc is None:
        return {"ok": False, "error": "no hay job corriendo"}
    _current_proc.terminate()
    return {"ok": True}
