"""
webtool/scenarios.py — canned attack scenarios matching webtool/TEST_PLAN.md
one-for-one, so the runbook can be triggered on demand from the API/UI
instead of copy-pasting curl commands by hand.

Each entry's `steps` is a list of /api/attack/start-shaped payloads
(domain/switch_indices/attack_type/target_ip/...), fired concurrently --
a single step for every scenario except 5b (the multi-domain one, which
TEST_PLAN.md itself launches with three backgrounded curls + `wait`).
Target IPs/switch indices are hardcoded to the exact values TEST_PLAN.md
documents, following topologies/star_topology.py's fixed convention
(ent_i=10.0.i.10, gnb_i=10.0.i.20, fixed_i=10.0.i.30) -- the same
assumption the manual runbook already makes.

Scenario 1 (no attack, just confirms the benign baseline is quiet) has
no steps -- it's informational only, not something this module runs.
"""

from typing import Dict, List, Optional, TypedDict


class ScenarioStep(TypedDict, total=False):
    domain: str
    switch_indices: List[int]
    attack_type: str
    target_ip: str
    dst_port: int
    count_per_node: int
    duration: Optional[int]


class Scenario(TypedDict):
    id: str
    group: str
    group_label: str
    label: str
    description: str
    expected: str
    steps: List[ScenarioStep]


SCENARIOS: List[Scenario] = [
    {
        "id": "1",
        "group": "1",
        "group_label": "1 — Baseline benigno",
        "label": "1 — Baseline benigno",
        "description": "Sin ataques. Confirma que el trafico legitimo (loops ICMP de enterprise/mobile, sesiones low_and_slow de broadband) no dispara ninguna deteccion falsa.",
        "expected": "0 lineas DETECTION en el log, active_attacks=[], trafico real visible hacia 10.99.0.1.",
        "steps": [],
    },
    {
        "id": "2a",
        "group": "2",
        "group_label": "2 — TCP SYN Flood (por dominio)",
        "label": "2a — SYN Flood (enterprise)",
        "description": "ent_1 -> ent_3, 20s.",
        "expected": "DETECTION SYN_FLOOD source=10.0.1.10 destination=10.0.3.10:443/TCP, BLOCK y luego UNBLOCK automatico.",
        "steps": [
            {"domain": "enterprise", "switch_indices": [1], "attack_type": "SYN", "target_ip": "10.0.3.10", "duration": 20},
        ],
    },
    {
        "id": "2b",
        "group": "2",
        "group_label": "2 — TCP SYN Flood (por dominio)",
        "label": "2b — SYN Flood (mobile)",
        "description": "gnb_2 -> ent_3, 20s.",
        "expected": "DETECTION SYN_FLOOD source=10.60.2.x, THROTTLE (sin UNBLOCK inmediato -- se libera por presencia, ver check_mobile_unblocks).",
        "steps": [
            {"domain": "mobile", "switch_indices": [2], "attack_type": "SYN", "target_ip": "10.0.3.10", "duration": 20},
        ],
    },
    {
        "id": "2c",
        "group": "2",
        "group_label": "2 — TCP SYN Flood (por dominio)",
        "label": "2c — SYN Flood (broadband)",
        "description": "sesion unica -> ent_4, 20s.",
        "expected": "DETECTION SYN_FLOOD source=10.61.1.14x, BLOCK y UNBLOCK ~60s despues (ventana fija).",
        "steps": [
            {"domain": "broadband", "switch_indices": [3], "attack_type": "SYN", "target_ip": "10.0.4.10", "duration": 20},
        ],
    },
    {
        "id": "3a",
        "group": "3",
        "group_label": "3 — UDP Flood (por dominio)",
        "label": "3a — UDP Flood (enterprise)",
        "description": "ent_2 -> ent_4, 20s.",
        "expected": "DETECTION UDP_FLOOD, BLOCK/UNBLOCK automatico.",
        "steps": [
            {"domain": "enterprise", "switch_indices": [2], "attack_type": "UDP", "target_ip": "10.0.4.10", "duration": 20},
        ],
    },
    {
        "id": "3b",
        "group": "3",
        "group_label": "3 — UDP Flood (por dominio)",
        "label": "3b — UDP Flood (mobile)",
        "description": "gnb_3 -> ent_1, 20s.",
        "expected": "DETECTION UDP_FLOOD, THROTTLE.",
        "steps": [
            {"domain": "mobile", "switch_indices": [3], "attack_type": "UDP", "target_ip": "10.0.1.10", "duration": 20},
        ],
    },
    {
        "id": "3c",
        "group": "3",
        "group_label": "3 — UDP Flood (por dominio)",
        "label": "3c — UDP Flood (broadband)",
        "description": "sesion unica -> ent_2, 20s.",
        "expected": "DETECTION UDP_FLOOD, BLOCK/UNBLOCK.",
        "steps": [
            {"domain": "broadband", "switch_indices": [1], "attack_type": "UDP", "target_ip": "10.0.2.10", "duration": 20},
        ],
    },
    {
        "id": "4a",
        "group": "4",
        "group_label": "4 — ICMP Flood (por dominio)",
        "label": "4a — ICMP Flood (enterprise)",
        "description": "ent_4 -> ent_1, 20s. Puede mostrar 2 detecciones (ida y vuelta) -- esperado, no un bug.",
        "expected": "DETECTION ICMP_FLOOD (posiblemente en ambos sentidos), BLOCK/UNBLOCK.",
        "steps": [
            {"domain": "enterprise", "switch_indices": [4], "attack_type": "ICMP", "target_ip": "10.0.1.10", "duration": 20},
        ],
    },
    {
        "id": "4b",
        "group": "4",
        "group_label": "4 — ICMP Flood (por dominio)",
        "label": "4b — ICMP Flood (mobile)",
        "description": "gnb_1 -> ent_2, 20s.",
        "expected": "DETECTION ICMP_FLOOD, THROTTLE.",
        "steps": [
            {"domain": "mobile", "switch_indices": [1], "attack_type": "ICMP", "target_ip": "10.0.2.10", "duration": 20},
        ],
    },
    {
        "id": "4c",
        "group": "4",
        "group_label": "4 — ICMP Flood (por dominio)",
        "label": "4c — ICMP Flood (broadband)",
        "description": "sesion unica -> ent_3, 20s.",
        "expected": "DETECTION ICMP_FLOOD, BLOCK/UNBLOCK.",
        "steps": [
            {"domain": "broadband", "switch_indices": [2], "attack_type": "ICMP", "target_ip": "10.0.3.10", "duration": 20},
        ],
    },
    {
        "id": "5a",
        "group": "5",
        "group_label": "5 — SYN distribuido",
        "label": "5a — SYN distribuido (enterprise, 4 fuentes)",
        "description": "Los 4 ent_i -> fixed_1 (10.0.1.30), 25s. Solo 4 fuentes -- por debajo de DIST_MIN_SOURCES=5.",
        "expected": "Hasta 4 SYN_FLOOD individuales, NO DDOS_DISTRIBUTED (limitacion estructural de la topologia, no una falla).",
        "steps": [
            {"domain": "enterprise", "switch_indices": [1, 2, 3, 4], "attack_type": "SYN", "target_ip": "10.0.1.30", "duration": 25},
        ],
    },
    {
        "id": "5b",
        "group": "5",
        "group_label": "5 — SYN distribuido",
        "label": "5b — SYN distribuido (mobile, 6 UEs)",
        "description": "6 UEs repartidas en gnb_1/gnb_3 (count_per_node=3) -> fixed_2 (10.0.2.30), 25s.",
        "expected": "DETECTION DDOS_DISTRIBUTED con >=5 fuentes 10.60.{1,3}.x, THROTTLE por UE contribuyente.",
        "steps": [
            {"domain": "mobile", "switch_indices": [1, 3], "attack_type": "SYN", "target_ip": "10.0.2.30", "count_per_node": 3, "duration": 25},
        ],
    },
    {
        "id": "5c",
        "group": "5",
        "group_label": "5 — SYN distribuido",
        "label": "5c — SYN distribuido (broadband, 8 sesiones)",
        "description": "distributed_syn_flood (8 sesiones BNG) -> fixed_3 (10.0.3.30), 30s.",
        "expected": "DETECTION DDOS_DISTRIBUTED con 8 fuentes 10.61.1.14x, BLOCK por sesion. Al terminar vuelve a low_and_slow.",
        "steps": [
            {"domain": "broadband", "switch_indices": [4], "attack_type": "SYN_DISTRIBUTED", "target_ip": "10.0.3.30", "duration": 30},
        ],
    },
    {
        "id": "5d",
        "group": "5",
        "group_label": "5 — SYN distribuido",
        "label": "5d — Multi-dominio contra el servidor central",
        "description": "Enterprise (4) + mobile (8, count_per_node=2) + broadband (8 sesiones), los 3 simultaneos -> 10.99.0.1:443, 30s.",
        "expected": "Una unica MULTIDOMAIN_DISTRIBUTED_ATTACK (posiblemente en 2 etapas -- mobile+broadband primero, enterprise se suma despues), mitigada por el mecanismo real de cada dominio.",
        "steps": [
            {"domain": "enterprise", "switch_indices": [1, 2, 3, 4], "attack_type": "SYN", "target_ip": "10.99.0.1", "dst_port": 443, "duration": 30},
            {"domain": "mobile", "switch_indices": [1, 2, 3, 4], "attack_type": "SYN", "target_ip": "10.99.0.1", "dst_port": 443, "count_per_node": 2, "duration": 30},
            {"domain": "broadband", "switch_indices": [1], "attack_type": "SYN_DISTRIBUTED", "target_ip": "10.99.0.1", "duration": 30},
        ],
    },
]

SCENARIOS_BY_ID: Dict[str, Scenario] = {s["id"]: s for s in SCENARIOS}
