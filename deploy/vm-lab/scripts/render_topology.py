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
LABADMIN_PASSWORD = "srslab-temp"  # plaintext of ROOT_PASSWORD_HASH above, for ansible_password

# Set interactively during tpl-alpine's setup-alpine -- there's no answerfile
# password field, so this can't be derived/generated here, it just has to
# match whatever was actually typed when the golden template was built.
ALPINE_ROOT_PASSWORD = "root"


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
        if net.get("control_node_ip") and i == 0:
            # via control_node_ip, not `gateway` -- see topology.yaml's
            # networks: comment. `gateway` is architectural/aspirational
            # (bng/core5g don't actually route); control_node_ip is the
            # only address on this VLAN that does real NAT today.
            netplan_lines.append(f"      routes: [{{to: default, via: {net['control_node_ip']}}}]")
            netplan_lines.append("      nameservers: {addresses: [8.8.8.8]}")

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
        # via control_node_ip, not `gateway` -- see topology.yaml's
        # networks: comment (gateway is architectural/aspirational, not
        # functional -- bng/core5g don't actually route).
        if net.get("control_node_ip"):
            iface_lines.append(f"    gateway {net['control_node_ip']}")

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

    # Lightweight post-clone customization -- NOT a re-run of setup-alpine.
    # Confirmed on a real ESXi host: re-running full setup-alpine against
    # an already-installed disk tries to redo the WHOLE install (re-
    # partition, re-download all base packages), which both fails outright
    # (no internet access yet on these brand-new internal VLANs -- DNS to
    # the apk mirror can't resolve) and is unnecessary anyway, since a
    # cloned disk already has every package the golden template had.
    # This just edits the 2 files that actually need to differ per clone.
    apply_sh = f"""#!/bin/sh
# Paste this into the VM's WEB CONSOLE (not SSH -- there's no network
# reachability yet, that's the whole point of running this) after first
# boot of a clone of {vm['role']}'s golden template.
echo "{vm['name']}" > /etc/hostname
hostname "{vm['name']}"
cat > /etc/network/interfaces <<'IFACES_EOF'
{chr(10).join(iface_lines)}
IFACES_EOF
echo "nameserver 8.8.8.8" > /etc/resolv.conf
rc-service networking restart
"""
    (vm_dir / "apply.sh").write_text(apply_sh)


def render_ansible_inventory(vms: list, templates: dict, out_dir: Path) -> None:
    by_role: dict = {}
    for vm in vms:
        by_role.setdefault(vm["role"], []).append(vm)

    lines = []
    for role, role_vms in sorted(by_role.items()):
        os_family = templates[role_vms[0]["template"]]["os_family"]
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
        # Alpine golden images keep their interactively-set root password;
        # Ubuntu/Debian clones get labadmin from cloud-init's user-data --
        # different os_families need different SSH creds, so this can't be
        # a single [all:vars] block (confirmed broken on a real run: every
        # host tried labadmin, which doesn't exist on Alpine VMs at all).
        lines.append(f"[{role}:vars]")
        if os_family == "alpine":
            lines.append("ansible_user=root")
            lines.append(f"ansible_password={ALPINE_ROOT_PASSWORD}")
        else:
            lines.append("ansible_user=labadmin")
            lines.append(f"ansible_password={LABADMIN_PASSWORD}")
        lines.append("")

    lines.append("[all:vars]")
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
        "br_mgmt_addr": mgmt_ip("br"),
        "br_peering_addr": net_ip("br", "PEERING"),
        "peer_router_peering_addr": net_ip("peer-router", "PEERING"),
        # br's real PEERING-facing NIC -- NOT guaranteed to be `ens192` on
        # a different ESXi host/rebuild (confirmed on this lab's own host:
        # vmxnet3 NICs get named by PCI slot, not sequentially -- verify
        # with `ip link show` on br itself before trusting this if the lab
        # was ever rebuilt). Must match config/settings.py's
        # PEERING_DIST_BR_EXTERNAL_IFACE.
        "peering_external_iface": "ens192",
        # pe/victim/enterprise_site's ENT_DC+MGMT NICs were hot-added
        # (govc vm.network.add) to already-running VMs rather than baked
        # into cloud-init/the alpine answerfile at clone time -- so
        # there's no render_cloud_init/render_alpine_answerfile path that
        # ever configures them, and their real OS-level names had to be
        # confirmed by hand per VM (same PCI-slot-naming unpredictability
        # as peering_external_iface above). Confirmed on this lab's real
        # host: pe's new NIC -> eth2, victim's -> eth1, all 5
        # ent-site-*'s new NIC -> ens192 (consistently). Re-verify with
        # `ip link show` before trusting these if the lab is ever rebuilt.
        "victim_ent_dc_addr": net_ip("victim", "ENT_DC"),
        "victim_ent_dc_iface": "eth1",
        "pe_ent_dc_iface": "eth2",
        "enterprise_mgmt_iface": "ens192",
        # ent-site's ORIGINAL (pre-hot-add) NIC -- always ens160 on this
        # host, unlike the hot-added ones above (first NIC naming has
        # been consistent across every VM in this lab).
        "enterprise_ent_lan_iface": "ens160",
        "mgmt_control_node_ip": topology["networks"]["MGMT"]["control_node_ip"],
        "ent_dc_cidr": topology["networks"]["ENT_DC"]["cidr"],
        # Broadband domain distributed mode -- accel-ppp + FreeRADIUS
        # (deploy/vm-lab/ansible/roles/bng + roles/suscriptor, and
        # config/settings.py's BNG_DIST_* on the app-code branch,
        # feature/peering-distributed-vm -- MUST stay numerically
        # identical to those, see that branch's own comments). REPLACES
        # the earlier BNGBlaster-based group_vars (bng_target_ip stays;
        # everything else here is new) -- see bngblaster_broadband_
        # pipeline_status memory for why BNGBlaster itself was dropped.
        "bng_target_ip": mgmt_ip("victim"),
        # bng's own 2nd NIC (BB_ACCESS). render_cloud_init's own
        # `ens{160+i}` naming COMMENT claims this should be sequential
        # (ens161) -- confirmed WRONG on a real run: this ESXi host's
        # vmxnet3 PCI-slot assignment gave it ens192 instead, same as
        # every hot-added NIC elsewhere in this lab. Confirmed via
        # `ip -br link show` on the real VM -- verify there again if
        # this VM is ever rebuilt, don't trust the naming formula.
        "bng_access_iface": "ens192",
        "bng_access_addr": net_ip("bng", "BB_ACCESS"),
        # accel-ppp's ip-pool range for subscriber leases -- same
        # 10.20.0.10-200 range dnsmasq used to hand out. Format is
        # accel-ppp's own ippool.c parse2(): "a.b.c.d-N" where N is ONLY
        # the last octet of the range's end (0-255), NOT a second full
        # IP address -- confirmed on a real run: "10.20.0.10-10.20.0.200"
        # (a full 2nd IP) silently mis-parsed as a 1-address range
        # (sscanf's "%u.%u.%u.%u-%u" stopped at the first "." after the
        # dash), causing every session to fail with "no free IPv4
        # address".
        "bng_pool_range": "10.20.0.10-200",
        # RADIUS shared secret between accel-ppp and FreeRADIUS, both on
        # `bng` itself (127.0.0.1) -- not security-sensitive (throwaway
        # local-simulation lab, same posture as BNGBlaster's own world-
        # writable control socket), just needs to match on both ends.
        "bng_radius_secret": "bng-lab-radius-secret",
        # suscriptor's physical access-facing NIC -- macvlan sub-
        # interfaces (one per simulated subscriber) are created on top
        # of this one (deploy/vm-lab/ansible/roles/suscriptor's own
        # tasks), each with its own MAC and DHCP lease from accel-ppp.
        # Unlike BNGBlaster, accel-ppp/DHCP has no objection to the
        # kernel owning addresses on this interface, so it no longer
        # needs the address-stripping BNGBlaster required. ens192,
        # confirmed via `ip -br link show` on the real VM -- same
        # PCI-slot-naming gotcha as bng_access_iface above, the
        # `ens{160+i}` sequential-naming comment in render_cloud_init
        # does NOT hold on this host even for NICs baked into cloud-init
        # at clone time.
        "suscriptor_access_iface": "ens192",
        # macvlan1..N (roles/suscriptor's setup_macvlans.sh.j2) -- must
        # match simulation/bng_ipoe_config.py's own _MAX_SUBSCRIBERS in
        # simulation/bng_subscriber_agent.py (the largest subscriber_
        # count any scenario there uses, distributed_*/low_and_slow's 8).
        "bng_subscriber_count": 8,
        "ent_lan_cidr": topology["networks"]["ENT_LAN"]["cidr"],
        "bgp_br_as": topology["bgp"]["br_as"],
        "bgp_peer_router_as": topology["bgp"]["peer_router_as"],
        # HTTPS, not the git@ SSH form -- these VMs won't have your own SSH
        # key by default. If the repo is private, either add a deploy
        # key/PAT to this URL or pre-seed each VM's known_hosts + key via
        # a separate Ansible task (not done here -- credentials don't
        # belong in topology.yaml).
        "tesis_controller_repo_url": "https://github.com/jmanu24/isp-ddos-ryu.git",
        # feature/peering-distributed-vm, not feature/bgp-peering-domain --
        # it's branched FROM that one (strict superset: everything it had,
        # plus PEERING_DISTRIBUTED_MODE support webtool/peering_ops.py
        # needs to run flow/exabgp against real VMs instead of Mininet).
        "tesis_controller_branch": "feature/peering-distributed-vm",
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

    render_ansible_inventory(vms, templates, OUT_DIR)
    render_ansible_group_vars(topology, OUT_DIR)
    render_govc_csv(vms, OUT_DIR)

    print(f"Generado en {OUT_DIR}:")
    print(f"  - cloud-init/  ({sum(1 for v in vms if templates[v['template']]['os_family'] in ('ubuntu','debian'))} VMs)")
    print(f"  - alpine/      ({sum(1 for v in vms if templates[v['template']]['os_family'] == 'alpine')} VMs)")
    print(f"  - ansible/inventory.ini  ({len(vms)} VMs, {len(set(v['role'] for v in vms))} roles)")
    print(f"  - govc/vms.csv")


if __name__ == "__main__":
    main()
