"""
webtool/inventory.py -- the 23-VM ESXi lab's node/network/domain map,
parsed live from ../topology.yaml (this lab's single source of truth for
VM names, roles and per-network interfaces -- cu2/ue2 included: they
were originally hot-added directly on ESXi outside this file, then
folded back into topology.yaml so it stays accurate). Only domain
grouping is a static overlay here, since topology.yaml has no "domain"
concept of its own, only `role:`.

Domain grouping (for the UI's 4-domain layout):
  mobile      -- ric, core5g, the 2 CU hosts (ran=cu1, cu2), 5 DU hosts,
                 the 2 UE hosts (each running several srsue netns)
  broadband   -- bng, suscriptor
  enterprise  -- ent-site-1..5
  bgp         -- br, peer-router
  shared      -- orchestrator, pe, victim (crossed by every domain's
                 attack traffic on its way to the one shared target)
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

SSH_USER = "labadmin"
SSH_PASSWORD = "srslab-temp"
# pe/victim run Alpine, provisioned with root/root (see inventory.ini) --
# not the same credential as every other (Ubuntu) VM in the lab.
ALT_CREDENTIALS = {
    "pe": ("root", "root"),
    "victim": ("root", "root"),
}

VICTIM_IP = "10.55.0.100"

VM_LAB_DIR = Path(__file__).resolve().parent.parent
TOPOLOGY_YAML = VM_LAB_DIR / "topology.yaml"

ROLE_TO_DOMAIN = {
    "orchestrator": "shared", "pe_ovs": "shared", "victim": "shared",
    "bng": "broadband", "suscriptor": "broadband",
    "br": "bgp", "peer_router": "bgp",
    "ric_oran_sc": "mobile", "core5g_open5gs": "mobile",
    "ran_srsran": "mobile", "du_srsran": "mobile", "ue_srsue": "mobile",
    "enterprise_site": "enterprise",
}

@dataclass
class UeNs:
    netns: str          # ue1..ue5
    host: str           # inventory hostname this netns lives on (ue|ue2)
    du_host: str         # paired DU inventory hostname


@dataclass
class Node:
    name: str
    role: str
    domain: str
    ip: str                                  # MGMT/ansible_host address
    interfaces: List[Dict[str, Optional[str]]] = field(default_factory=list)  # [{network, ip}]
    govc_name: Optional[str] = None


def _load_topology():
    with open(TOPOLOGY_YAML) as f:
        return yaml.safe_load(f)


def _build_nodes() -> List[Node]:
    doc = _load_topology()
    networks = doc.get("networks", {})
    nodes = []
    for vm in doc.get("vms", []):
        role = vm["role"]
        domain = ROLE_TO_DOMAIN.get(role, "shared")
        ifaces = [{"network": i["network"], "ip": i.get("ip")} for i in vm.get("interfaces", [])]
        mgmt_ip = next((i["ip"] for i in ifaces if i["network"] == "MGMT" and i.get("ip")), None)
        nodes.append(Node(name=vm["name"], role=role, domain=domain, ip=mgmt_ip, interfaces=ifaces))
    return nodes, networks


NODES, NETWORKS = _build_nodes()
NODES_BY_NAME: Dict[str, Node] = {n.name: n for n in NODES}

# Which VM each srsue netns actually runs on, and which DU it is paired
# with -- mirrors reconnect_mobile_domain.yml's loop_var table exactly
# (mobile-bringup-order memory).
UE_NETNS: List[UeNs] = [
    UeNs("ue1", "ue", "du"),
    UeNs("ue2", "ue", "du2"),
    UeNs("ue3", "ue", "du3"),
    UeNs("ue4", "ue2", "du4"),
    UeNs("ue5", "ue2", "du5"),
]

# The strict bring-up order (mobile-bringup-order memory), as
# (step_label, ansible_tags) pairs -- used both to render the ordered
# button list and to drive "bring up to here" (every tag up to and
# including the clicked one).
BRINGUP_STEPS = [
    ("5gcore", "core"),
    ("ric", "ric"),
    ("cu1", "cu1"),
    ("du1", "du1"),
    ("ue1", "ue1"),
    ("du2", "du2"),
    ("ue2", "ue2"),
    ("du3", "du3"),
    ("ue3", "ue3"),
    ("cu2", "cu2"),
    ("du4", "du4"),
    ("ue4", "ue4"),
    ("du5", "du5"),
    ("ue5", "ue5"),
    ("xapps (KPM bridge)", "xapps"),
]

DOMAINS = ["shared", "mobile", "broadband", "enterprise", "bgp"]


def nodes_by_domain(domain: str) -> List[Node]:
    return [n for n in NODES if n.domain == domain]


def credentials_for(node_name: str):
    return ALT_CREDENTIALS.get(node_name, (SSH_USER, SSH_PASSWORD))


def to_topology_dict() -> dict:
    """JSON-serializable topology for the UI's graph view -- nodes carry
    their full interface list so the frontend can draw real per-network
    edges (a hub node per VLAN, same idea as the mininet webtool's own
    switch-hub graph), not a made-up star."""
    domains = {}
    for d in DOMAINS:
        domains[d] = [
            {"name": n.name, "role": n.role, "ip": n.ip, "interfaces": n.interfaces}
            for n in nodes_by_domain(d)
        ]
    return {
        "domains": domains,
        "networks": {name: {"cidr": cfg.get("cidr"), "promiscuous": cfg.get("promiscuous", False)}
                     for name, cfg in NETWORKS.items()},
        "ue_netns": [
            {"netns": u.netns, "host": u.host, "du_host": u.du_host}
            for u in UE_NETNS
        ],
        "victim_ip": VICTIM_IP,
    }
