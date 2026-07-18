"""
webtool/state.py — in-memory state for the standalone attack-launcher
web app. Independent of web/state.py (the existing read-only dashboard
embedded in the ryu-manager process) -- this app never imports from
web/, it only ever talks to it as a black-box HTTP client (see
webtool/app.py's reconciliation loop).

Log format (homologated with ryu-manager output):
  YYYY-MM-DD HH:MM:SS LEVEL [webtool] EVENT_TYPE: message
"""

import threading
from datetime import datetime

# Webtool events go to a SEPARATE file so they never interleave with
# ryu-manager's stdout (which writes to webtool_controller.log via the
# subprocess file handle).  The parser merges both files by timestamp.
_EVENTS_PATH = "/tmp/webtool_events.log"
_events_lock = threading.Lock()


def _log_event(msg: str) -> None:
    line = datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " INFO [webtool] " + msg + "\n"
    with _events_lock:
        with open(_EVENTS_PATH, "a") as f:
            f.write(line)


class WebToolState:

    def __init__(self):
        self.controller_status = "stopped"   # stopped|starting|running|error
        self.topology_status = "stopped"     # stopped|starting|running|error
        self.nodes = {}            # node_id -> {id, domain, switch_index, ip}
        self.active_attacks = {}   # attack_id -> {domain, switch_indices, attack_type, started_at, duration, target_ip}
        self.events = []           # rolling list, same pattern web/state.py's add_event uses
        self.active_blocks = []    # snapshot from web/api /api/blocks, polled each cycle

    def add_event(self, text: str, level: str = "INFO") -> None:
        self.events.append({"timestamp": datetime.now().isoformat(), "message": text})
        self.events = self.events[-500:]
        _log_event(text)

    def set_controller_status(self, status: str) -> None:
        self.controller_status = status
        self.add_event(f"CONTROLLER_STATUS: status={status}")

    def set_topology_status(self, status: str) -> None:
        self.topology_status = status
        self.add_event(f"TOPOLOGY_STATUS: status={status}")

    def set_nodes(self, nodes: dict) -> None:
        self.nodes = nodes

    def add_attack(self, attack_id: str, info: dict, scenario: str = "manual") -> None:
        self.active_attacks[attack_id] = {"attack_id": attack_id, **info}
        self.add_event(
            f"ATTACK_START: scenario={scenario} domain={info.get('domain')} "
            f"switches={info.get('switch_indices')} tipo={info.get('attack_type')} "
            f"target={info.get('target_ip')} attack_id={attack_id}"
        )

    def remove_attack(self, attack_id: str, scenario: str = "manual") -> None:
        info = self.active_attacks.pop(attack_id, None)
        if info:
            self.add_event(
                f"ATTACK_STOP: scenario={scenario} domain={info.get('domain')} "
                f"switches={info.get('switch_indices')} tipo={info.get('attack_type')} "
                f"target={info.get('target_ip')} attack_id={attack_id}"
            )

    def set_active_blocks(self, blocks: list) -> None:
        self.active_blocks = blocks

    def to_dict(self) -> dict:
        return {
            "controller_status": self.controller_status,
            "topology_status": self.topology_status,
            "nodes": list(self.nodes.values()),
            "active_attacks": list(self.active_attacks.values()),
            "events": self.events[-20:],
            "active_blocks": self.active_blocks,
        }


webtool_state = WebToolState()
