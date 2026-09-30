"""
webtool/state.py -- in-memory state for the vm-lab webtool, same rolling-
event-log pattern as the mininet webtool's own webtool/state.py (this is
a SEPARATE app for a SEPARATE lab -- no import between the two).
"""

import threading
from datetime import datetime

_events_lock = threading.Lock()


class VmLabState:
    def __init__(self):
        self.lock = threading.RLock()
        self.node_status = {}      # node_name -> {power, checks: {...}, checked_at}
        self.metrics = {}          # node_name -> {cpu_pct, mem_pct, iface: {name: {rx_bps, tx_bps}}, history: [...]}
        self.active_attacks = {}   # attack_id -> {domain, source, attack_type, target_ip, started_at, pids: [(node,pid)]}
        self.kpm_samples = []      # rolling list of latest /kpm poll
        self.mitigation_events = []  # rolling list from actuator/detector logs
        self.events = []           # rolling generic event log
        self.ansible_job = None    # {id, label, running, lines: [...], rc}

    def add_event(self, text: str) -> None:
        with self.lock:
            self.events.append({"timestamp": datetime.now().isoformat(), "message": text})
            self.events = self.events[-500:]

    def set_node_status(self, node_name: str, status: dict) -> None:
        with self.lock:
            self.node_status[node_name] = status

    def set_metrics(self, node_name: str, sample: dict) -> None:
        with self.lock:
            entry = self.metrics.setdefault(node_name, {"history": []})
            entry.update(sample)
            entry["history"].append({"t": sample.get("t"), "cpu_pct": sample.get("cpu_pct"),
                                      "mem_pct": sample.get("mem_pct"), "iface": sample.get("iface")})
            entry["history"] = entry["history"][-120:]  # ~20 min at 10s cadence

    def add_attack(self, attack_id: str, info: dict) -> None:
        with self.lock:
            self.active_attacks[attack_id] = {"attack_id": attack_id, **info}
        self.add_event(f"ATTACK_START: domain={info.get('domain')} tipo={info.get('attack_type')} "
                        f"target={info.get('target_ip')} attack_id={attack_id}")

    def remove_attack(self, attack_id: str) -> dict:
        with self.lock:
            info = self.active_attacks.pop(attack_id, None)
        if info:
            self.add_event(f"ATTACK_STOP: domain={info.get('domain')} tipo={info.get('attack_type')} "
                            f"attack_id={attack_id}")
        return info

    def set_kpm_samples(self, samples: list) -> None:
        with self.lock:
            self.kpm_samples = samples

    def add_mitigation_events(self, lines: list) -> None:
        if not lines:
            return
        with self.lock:
            self.mitigation_events.extend({"timestamp": datetime.now().isoformat(), "message": l} for l in lines)
            self.mitigation_events = self.mitigation_events[-200:]

    def set_ansible_job(self, job: dict) -> None:
        with self.lock:
            self.ansible_job = job

    def append_ansible_line(self, line: str) -> None:
        with self.lock:
            if self.ansible_job is not None:
                self.ansible_job["lines"].append(line)
                self.ansible_job["lines"] = self.ansible_job["lines"][-2000:]

    def to_dict(self) -> dict:
        with self.lock:
            return {
                "node_status": self.node_status,
                "metrics": {k: {kk: vv for kk, vv in v.items() if kk != "history"} for k, v in self.metrics.items()},
                "active_attacks": list(self.active_attacks.values()),
                "kpm_samples": self.kpm_samples,
                "mitigation_events": self.mitigation_events[-30:],
                "events": self.events[-30:],
                "ansible_job": self.ansible_job,
            }


vmlab_state = VmLabState()
