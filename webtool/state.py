"""
webtool/state.py — in-memory state for the standalone attack-launcher
web app. Independent of web/state.py (the existing read-only dashboard
embedded in the ryu-manager process) -- this app never imports from
web/, it only ever talks to it as a black-box HTTP client (see
webtool/app.py's reconciliation loop).
"""

import logging
from datetime import datetime

_LOG_PATH = "/tmp/webtool_controller.log"

logging.basicConfig(
    filename=_LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_log = logging.getLogger("webtool")


class WebToolState:

    def __init__(self):
        self.controller_status = "stopped"   # stopped|starting|running|error
        self.topology_status = "stopped"     # stopped|starting|running|error
        self.nodes = {}            # node_id -> {id, domain, switch_index, ip}
        self.active_attacks = {}   # attack_id -> {domain, switch_indices, attack_type, started_at, duration, target_ip}
        self.events = []           # rolling list, same pattern web/state.py's add_event uses
        self.active_blocks = []    # snapshot from web/api /api/blocks, polled each cycle

    def add_event(self, text: str) -> None:
        self.events.append({"timestamp": datetime.now().isoformat(), "message": text})
        self.events = self.events[-500:]
        _log.info(text)

    def set_controller_status(self, status: str) -> None:
        self.controller_status = status
        self.add_event(f"Controlador: {status}")

    def set_topology_status(self, status: str) -> None:
        self.topology_status = status
        self.add_event(f"Topologia: {status}")

    def set_nodes(self, nodes: dict) -> None:
        self.nodes = nodes

    def add_attack(self, attack_id: str, info: dict) -> None:
        self.active_attacks[attack_id] = {"attack_id": attack_id, **info}
        self.add_event(
            f"Ataque iniciado [{info.get('domain')}] switches={info.get('switch_indices')} "
            f"tipo={info.get('attack_type')} -> {info.get('target_ip')}"
        )

    def remove_attack(self, attack_id: str) -> None:
        info = self.active_attacks.pop(attack_id, None)
        if info:
            self.add_event(f"Ataque detenido [{info.get('domain')}] switches={info.get('switch_indices')}")

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
