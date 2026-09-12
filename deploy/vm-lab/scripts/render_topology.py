#!/usr/bin/env python3
"""
render_topology.py -- reads ../topology.yaml (the single source of truth
for the 16-VM ESXi lab) and generates everything derived from it:

  generated/cloud-init/<vm>/user-data   (Ubuntu/Debian VMs -- NoCloud format)
  generated/cloud-init/<vm>/meta-data
  generated/alpine/<vm>/answerfile      (Alpine VMs -- static IP)
  generated/ansible/inventory.ini       (grouped by role, matches ansible/roles/*)
  generated/govc/vms.csv                (name,template,vcpu,ram_mb,disk_gb --
                                          consumed by ../deploy_govc.sh)

Re-run this any time topology.yaml changes -- never hand-edit anything
under generated/, it's all overwritten on each run.

Requires: pyyaml (pip install pyyaml)

Usage:
  python3 render_topology.py
"""
import ipaddress
import sys
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
LAB_DIR = SCRIPT_DIR.parent
TOPOLOGY_PATH = LAB_DIR / "topology.yaml"
OUT_DIR = LAB_DIR / "generated"

# Same verified SHA-512 crypt of "srslab-temp" used by the Packer
# templates' own http/ files -- keep in sync if you change the lab's
# shared temporary password. Real deployments should replace this with
# per-user SSH keys before anything faces a real network.
ROOT_PASSWORD_HASH = (
    "$6$a138b4a7baaaffef$FL199Um6qdvW1l4n2upNs2B44BmQmF74DxIYY2CkoXSCBLLL/"
    "kWyC6h2pqIDmtiOcYZgz3p6//r1fF6o4P2NP1"
)


def _prefix_len(cidr: str) -> int:
    return ipaddress.ip_network(cidr, strict=False).prefixlen


def render_cloud_init(vm: dict, networks: dict, out_dir: Path) -> None:
    """Ubuntu/Debian VMs: NoCloud user-data/meta-data. Injected at clone
    time via `govc vm.change -e guestinfo.userdata=<base64>` (see
    deploy_govc.sh) -- cloud-init on these images already knows to read
    the VMware guestinfo NoCloud datasource (no HTTP server needed at
    deploy time, unlike the Packer build step's own datasource)."""
    vm_dir = out_dir / "cloud-init" / vm["name"]
    vm_dir.mkdir(parents=True, exist_ok=True)

    netplan_lines = ["network:", "  version: 2", "  ethernets:"]
    for i, iface in enumerate(vm["interfaces"]):
        net = networks[iface["network"]]
        ifname = f"ens{160 + i}" if i > 0 else "ens160"  # vmxnet3 default naming
        netplan_lines.append(f"    {ifname}:")
        if iface["ip"] is None:
            netplan_lines.append("      dhcp4: true")
            continue
        prefix = _prefix_len(net["cidr"])
        netplan_lines.append(f"      addresses: [{iface['ip']}/{prefix}]")
        if net.get("gateway") and i == 0:
            netplan_lines.append(f"      routes: [{{to: default, via: {net['gateway']}}}]")

    user_data = f"""#cloud-config
hostname: {vm['name']}
manage_etc_hosts: true
users:
  - name: labadmin
    groups: [sudo]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: false
    passwd: "{ROOT_PASSWORD_HASH}"
ssh_pwauth: true
write_files:
  - path: /etc/netplan/99-lab.yaml
    content: |
{chr(10).join('      ' + l for l in netplan_lines)}
runcmd:
  - netplan apply
"""
    (vm_dir / "user-data").write_text(user_data)
    (vm_dir / "meta-data").write_text(f"instance-id: {vm['name']}\nlocal-hostname: {vm['name']}\n")


def render_alpine_answerfile(vm: dict, networks: dict, out_dir: Path) -> None:
    """Alpine VMs: static-IP answerfile for a re-run of `setup-alpine -f`
    against the already-imaged disk (or for a from-scratch install if you
    prefer per-VM Alpine installs over cloning tpl-alpine -- see
    ../README.md's two deployment options)."""
    vm_dir = out_dir / "alpine" / vm["name"]
    vm_dir.mkdir(parents=True, exist_ok=True)

    primary = vm["interfaces"][0]
    net = networks[primary["network"]]
    iface_lines = ["auto lo", "iface lo inet loopback", "", "auto eth0"]
    if primary["ip"] is None:
        iface_lines.append("iface eth0 inet dhcp")
    else:
        prefix = _prefix_len(net["cidr"])
        iface_lines.append("iface eth0 inet static")
        iface_lines.append(f"    address {primary['ip']}")
        iface_lines.append(f"    netmask {ipaddress.ip_network(net['cidr'], strict=False).netmask}")
        if net.get("gateway"):
            iface_lines.append(f"    gateway {net['gateway']}")

    for i, iface in enumerate(vm["interfaces"][1:], start=1):
        net2 = networks[iface["network"]]
        iface_lines += ["", f"auto eth{i}"]
        if iface["ip"] is None:
            iface_lines.append(f"iface eth{i} inet manual")  # bridged (e.g. pe's ENT_LAN port)
        else:
            prefix2 = _prefix_len(net2["cidr"])
            iface_lines.append(f"iface eth{i} inet static")
            iface_lines.append(f"    address {iface['ip']}")
            iface_lines.append(f"    netmask {ipaddress.ip_network(net2['cidr'], strict=False).netmask}")

    answerfile = f"""KEYMAPOPTS="us us"
HOSTNAMEOPTS="{vm['name']}"
INTERFACESOPTS="{chr(10).join(iface_lines)}
"
DNSOPTS="-d local 1.1.1.1"
TIMEZONEOPTS="-z UTC"
PROXYOPTS="none"
APKREPOSOPTS="-1"
SSHDOPTS="-c openssh"
NTPOPTS="-c chrony"
DISKOPTS="-m sys /dev/sda"
LBUOPTS="none"
APKCACHEOPTS="none"
"""
    (vm_dir / "answerfile").write_text(answerfile)


def render_ansible_inventory(vms: list, out_dir: Path) -> None:
    by_role: dict = {}
    for vm in vms:
        by_role.setdefault(vm["role"], []).append(vm)

    lines = []
    for role, role_vms in sorted(by_role.items()):
        lines.append(f"[{role}]")
        for vm in role_vms:
            mgmt_ip = next(
                (i["ip"] for i in vm["interfaces"] if i["ip"] is not None),
                None,
            )
            if mgmt_ip is None:
                lines.append(f"# {vm['name']} has no IP-addressed interface -- add one to reach it via Ansible")
                continue
            lines.append(f"{vm['name']} ansible_host={mgmt_ip}")
        lines.append("")

    lines.append("[all:vars]")
    lines.append("ansible_user=labadmin")
    lines.append("ansible_ssh_common_args='-o StrictHostKeyChecking=no'")

    ansible_dir = out_dir / "ansible"
    ansible_dir.mkdir(parents=True, exist_ok=True)
    (ansible_dir / "inventory.ini").write_text("\n".join(lines) + "\n")


def render_ansible_group_vars(topology: dict, out_dir: Path) -> None:
    """Cross-VM addresses/AS numbers that Jinja2 templates in
    ansible/roles/*/templates/ need (e.g. ran_srsran's gnb_zmq.yaml.j2
    needs core5g's and ric's MGMT addresses) -- generated here so they
    can never drift from topology.yaml's own values."""
    by_name = {vm["name"]: vm for vm in topology["vms"]}

    def mgmt_ip(vm_name: str) -> str:
        vm = by_name[vm_name]
        return next(i["ip"] for i in vm["interfaces"] if i["ip"] is not None)

    def net_ip(vm_name: str, network: str) -> str:
        vm = by_name[vm_name]
        return next(i["ip"] for i in vm["interfaces"] if i["network"] == network)

    group_vars = {
        "core5g_addr": mgmt_ip("core5g"),
        "core5g_ran_addr": net_ip("core5g", "RAN"),
        "ran_mgmt_addr": mgmt_ip("ran"),
        "ric_addr": mgmt_ip("ric"),
        "orchestrator_addr": mgmt_ip("orchestrator"),
        "bgp_br_as": topology["bgp"]["br_as"],
        "bgp_peer_router_as": topology["bgp"]["peer_router_as"],
        # HTTPS, not the git@ SSH form -- these VMs won't have your own SSH
        # key by default. If the repo is private, either add a deploy
        # key/PAT to this URL or pre-seed each VM's known_hosts + key via
        # a separate Ansible task (not done here -- credentials don't
        # belong in topology.yaml).
        "tesis_controller_repo_url": "https://github.com/jmanu24/isp-ddos-ryu.git",
        "tesis_controller_branch": "feature/bgp-peering-domain",
    }

    group_vars_dir = out_dir / "ansible" / "group_vars"
    group_vars_dir.mkdir(parents=True, exist_ok=True)
    lines = ["---", "# Generated by render_topology.py -- do not hand-edit, edit topology.yaml"]
    for k, v in group_vars.items():
        lines.append(f'{k}: "{v}"' if isinstance(v, str) else f"{k}: {v}")
    (group_vars_dir / "all.yml").write_text("\n".join(lines) + "\n")


def render_govc_csv(vms: list, out_dir: Path) -> None:
    govc_dir = out_dir / "govc"
    govc_dir.mkdir(parents=True, exist_ok=True)
    lines = ["name,template,vcpu,ram_mb,disk_gb"]
    for vm in vms:
        lines.append(f"{vm['name']},{vm['template']},{vm['vcpu']},{vm['ram_mb']},{vm['disk_gb']}")
    (govc_dir / "vms.csv").write_text("\n".join(lines) + "\n")


def main() -> None:
    if not TOPOLOGY_PATH.exists():
        print(f"ERROR: {TOPOLOGY_PATH} not found", file=sys.stderr)
        sys.exit(1)

    topology = yaml.safe_load(TOPOLOGY_PATH.read_text())
    networks = topology["networks"]
    vms = topology["vms"]
    templates = topology["templates"]

    for vm in vms:
        os_family = templates[vm["template"]]["os_family"]
        if os_family in ("ubuntu", "debian"):
            render_cloud_init(vm, networks, OUT_DIR)
        elif os_family == "alpine":
            render_alpine_answerfile(vm, networks, OUT_DIR)
        else:
            raise ValueError(f"unknown os_family {os_family!r} for template {vm['template']!r}")

    render_ansible_inventory(vms, OUT_DIR)
    render_ansible_group_vars(topology, OUT_DIR)
    render_govc_csv(vms, OUT_DIR)

    print(f"Generado en {OUT_DIR}:")
    print(f"  - cloud-init/  ({sum(1 for v in vms if templates[v['template']]['os_family'] in ('ubuntu','debian'))} VMs)")
    print(f"  - alpine/      ({sum(1 for v in vms if templates[v['template']]['os_family'] == 'alpine')} VMs)")
    print(f"  - ansible/inventory.ini  ({len(vms)} VMs, {len(set(v['role'] for v in vms))} roles)")
    print(f"  - govc/vms.csv")


if __name__ == "__main__":
    main()
