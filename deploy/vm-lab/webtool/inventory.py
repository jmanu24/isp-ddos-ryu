"""
webtool/inventory.py -- static map of the 16-VM ESXi lab, derived by hand
from ../topology.yaml + ../generated/ansible/inventory.ini (both already
committed as this lab's own single sources of truth). Kept as a small
static table rather than re-parsed live on every request: topology.yaml
changes require re-running scripts/render_topology.py and a real
redeploy anyway (see its own header comment -- "never hand-edit the
generated files"), so the VM set is effectively fixed between deploys.

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
from typing import Dict, List, Optional

SSH_USER = "labadmin"
SSH_PASSWORD = "srslab-temp"
# pe/victim run Alpine, provisioned with root/root (see inventory.ini) --
# not the same credential as every other (Ubuntu) VM in the lab.
ALT_CREDENTIALS = {
    "pe": ("root", "root"),
    "victim": ("root", "root"),
}

VICTIM_IP = "10.55.0.100"


@dataclass
class UeNs:
    netns: str          # ue1..ue5
    host: str           # inventory hostname this netns lives on (ue|ue2)
    du_host: str         # paired DU inventory hostname
    ip: Optional[str] = None  # 10.45.1.x once attached (informational only)


@dataclass
class Node:
    name: str            # inventory hostname == govc VM name
    role: str            # ansible role / inventory group
    domain: str          # mobile|broadband|enterprise|bgp|shared
    ip: str              # MGMT/ansible_host address
    kind: str = "vm"     # vm -- reserved for future non-VM rows
    govc_name: Optional[str] = None  # defaults to `name` when unset


NODES: List[Node] = [
    Node("orchestrator", "orchestrator", "shared", "10.10.0.1"),
    Node("pe", "pe_ovs", "shared", "10.10.0.7"),
    Node("victim", "victim", "shared", "10.10.0.100"),

    Node("bng", "bng", "broadband", "10.10.0.2"),
    Node("suscriptor", "suscriptor", "broadband", "10.10.0.9"),

    Node("br", "br", "bgp", "10.10.0.3"),
    Node("peer-router", "peer_router", "bgp", "10.30.0.2"),

    Node("ric", "ric_flexric", "mobile", "10.10.0.4"),
    Node("core5g", "core5g_open5gs", "mobile", "10.10.0.5"),
    Node("ran", "ran_srsran", "mobile", "10.10.0.6"),   # cu1
    Node("cu2", "ran_srsran", "mobile", "10.10.0.15"),
    Node("du", "du_srsran", "mobile", "10.10.0.10"),    # du1
    Node("du2", "du_srsran", "mobile", "10.10.0.11"),
    Node("du3", "du_srsran", "mobile", "10.10.0.12"),
    Node("du4", "du_srsran", "mobile", "10.10.0.13"),
    Node("du5", "du_srsran", "mobile", "10.10.0.14"),
    Node("ue", "ue_srsue", "mobile", "10.10.0.8"),      # hosts ue1/ue2/ue3
    Node("ue2", "ue_srsue", "mobile", "10.10.0.16"),    # hosts ue4/ue5

    Node("ent-site-1", "enterprise_site", "enterprise", "10.10.0.21"),
    Node("ent-site-2", "enterprise_site", "enterprise", "10.10.0.22"),
    Node("ent-site-3", "enterprise_site", "enterprise", "10.10.0.23"),
    Node("ent-site-4", "enterprise_site", "enterprise", "10.10.0.24"),
    Node("ent-site-5", "enterprise_site", "enterprise", "10.10.0.25"),
]

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
    """JSON-serializable topology for the UI's graph view."""
    domains = {}
    for d in DOMAINS:
        domains[d] = [
            {"name": n.name, "role": n.role, "ip": n.ip}
            for n in nodes_by_domain(d)
        ]
    return {
        "domains": domains,
        "ue_netns": [
            {"netns": u.netns, "host": u.host, "du_host": u.du_host}
            for u in UE_NETNS
        ],
        "victim_ip": VICTIM_IP,
    }
