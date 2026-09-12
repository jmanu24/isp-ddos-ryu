#!/usr/bin/env bash
#
# deploy_govc.sh -- provisions the 16 VMs from their golden templates
# directly on a standalone ESXi host (no vCenter), sizing each per
# ../topology.yaml (via generated/govc/vms.csv, see
# scripts/render_topology.py) and injecting its per-VM cloud-init
# (Ubuntu/Debian) via VMware guestinfo.
#
# CLONING METHOD: NOT govc vm.clone. Confirmed against a real ESXi 7.0.3
# host (and independently confirmed by a govmomi maintainer:
# https://github.com/vmware/govmomi/issues/1469#issuecomment-...) that
# standalone ESXi does not support the CloneVM_Task API at all --
# regardless of license -- it is vCenter-only. This script instead uses
# the standard bare-ESXi workaround: copy the golden template's VMDK at
# the datastore level via `vmkfstools -i` (over SSH to the host's own
# shell -- this is NOT exposed through the vSphere API/govc, hence the
# SSH requirement below), then `govc vm.register` the copied disk as a
# new VM. Also confirmed the REST/vAPI login (`/rest/com/vmware/cis/
# session`, `/api/session`) that `packer`'s vsphere-iso builder hard-
# requires is unavailable here too (CIS session auth is fundamentally a
# vCenter/PSC concept) -- so the 3 golden templates themselves were built
# by hand via the ESXi web console, not by this script or Packer.
#
# Prerequisites:
#   - govc installed (https://github.com/vmware/govmomi/releases)
#   - sshpass installed (`apt install sshpass`) -- for non-interactive
#     SSH to the ESXi host's own shell (vmkfstools has no API equivalent)
#   - SSH enabled on the ESXi host (TSM-SSH service) -- `govc
#     host.service.ls | grep ssh` to check, enable via the DCUI or web UI
#     if not already on
#   - The 3 golden templates (tpl-alpine, tpl-ubuntu-2204, tpl-debian-13)
#     already built BY HAND (see ../README.md's "Known risk areas") and
#     present on the ESXi host, powered off
#   - python3 scripts/render_topology.py already run (needs generated/ to exist)
#   - GOVC_URL / GOVC_INSECURE / GOVC_DATASTORE exported
#   - ESXI_HOST and ESXI_SSH_PASSWORD exported (root's SSH password --
#     yes, the same credential as GOVC_URL's; kept separate rather than
#     parsed out of GOVC_URL to avoid fragile URL-parsing for a password
#     that may itself contain `@`/`:`/other URL-special characters)
#
# Usage:
#   export GOVC_URL="https://192.168.18.135/sdk"
#   export GOVC_USERNAME=root GOVC_PASSWORD='...' GOVC_INSECURE=1
#   export GOVC_DATASTORE=datastore1
#   export ESXI_HOST=192.168.18.135 ESXI_SSH_PASSWORD='...'
#   ./deploy_govc.sh                    # deploy all 16
#   ./deploy_govc.sh br ran             # deploy only these VMs (re-run/repair)
#   ./deploy_govc.sh --portgroups       # just print the portgroup names this
#                                       # script expects to already exist on
#                                       # the ESXi vSwitch, then exit
#
# NOTE ON NETWORKING: this script assumes 5 port groups already exist on
# the ESXi host's vSwitch(es), matching topology.yaml's `networks:` block
# (portgroup names VLAN-MGMT, VLAN-BB-ACCESS, VLAN-PEERING, VLAN-RAN,
# VLAN-ENT-LAN). Create them yourself first (`govc host.portgroup.add` or
# the ESXi host UI) -- this script only wires VMs to networks that already
# exist, it does not create switches/port groups.
#
# NOTE ON THE CONTROL NODE (wherever this script and ansible-playbook
# actually run from): it needs its own IP address on EVERY one of the 5
# VLANs above to reach every VM directly (SSH/Ansible), not just VLAN-MGMT
# -- confirmed necessary on a real run once VMs on VLAN-BB-ACCESS/
# PEERING/RAN/ENT-LAN turned out unreachable from a control node that only
# had an MGMT-side address. If the control node is itself a VM on this
# same ESXi host, give it one additional vNIC per VLAN (`govc
# vm.network.add`) and a static IP in each (this script does not do that
# for you -- it's a one-time setup step, not a per-VM-deploy operation).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
VMS_CSV="${LAB_DIR}/generated/govc/vms.csv"
TOPOLOGY_YAML="${LAB_DIR}/topology.yaml"
CLOUD_INIT_DIR="${LAB_DIR}/generated/cloud-init"
ALPINE_DIR="${LAB_DIR}/generated/alpine"

DATASTORE="${GOVC_DATASTORE:-datastore1}"

if [ "${1:-}" = "--portgroups" ]; then
  echo "Port groups esperados (crear antes de correr este script):"
  python3 - "$TOPOLOGY_YAML" <<'PYEOF'
import sys, yaml
t = yaml.safe_load(open(sys.argv[1]))
for name, net in t["networks"].items():
    print(f"  {net['portgroup']}  ({net['cidr']})")
PYEOF
  exit 0
fi

if [ ! -f "$VMS_CSV" ]; then
  echo "ERROR: $VMS_CSV no existe -- corre primero: python3 scripts/render_topology.py" >&2
  exit 1
fi

command -v govc >/dev/null 2>&1 || { echo "ERROR: govc no está en PATH -- https://github.com/vmware/govmomi/releases" >&2; exit 1; }
command -v sshpass >/dev/null 2>&1 || { echo "ERROR: sshpass no está en PATH -- sudo apt install sshpass" >&2; exit 1; }
: "${GOVC_URL:?export GOVC_URL primero}"
: "${ESXI_HOST:?export ESXI_HOST=<ip del host ESXi> primero}"
: "${ESXI_SSH_PASSWORD:?export ESXI_SSH_PASSWORD='...' primero (password de root para SSH al host ESXi)}"

esxi_ssh() {
  sshpass -p "$ESXI_SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    "root@${ESXI_HOST}" "$@"
}

FILTER=("$@")

# name -> template os_family, and per-VM interfaces (network:ip pairs, in
# topology.yaml order) -- read once via python/yaml rather than re-parsing
# YAML in bash for every VM.
VM_META_JSON="$(python3 - "$TOPOLOGY_YAML" <<'PYEOF'
import json, sys, yaml
t = yaml.safe_load(open(sys.argv[1]))
templates = t["templates"]
networks = t["networks"]
out = {}
for vm in t["vms"]:
    out[vm["name"]] = {
        "os_family": templates[vm["template"]]["os_family"],
        "source_vm": templates[vm["template"]]["source_vm"],
        "interfaces": [
            {"portgroup": networks[i["network"]]["portgroup"]}
            for i in vm["interfaces"]
        ],
    }
print(json.dumps(out))
PYEOF
)"

deploy_one() {
  local name="$1" template_key="$2" vcpu="$3" ram_mb="$4" disk_gb="$5"

  local os_family source_vm
  os_family="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['$name']['os_family'])" "$VM_META_JSON")"
  source_vm="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['$name']['source_vm'])" "$VM_META_JSON")"

  echo "== $name (de $source_vm, ${vcpu}vCPU/${ram_mb}MB/${disk_gb}GB) =="

  # `govc vm.info <name>` exits 0 even when nothing matches -- it just
  # prints nothing -- confirmed empirically against a real ESXi host, so
  # checking the exit code alone always thought every VM already existed
  # and silently skipped creating all 16. Check for non-empty output instead.
  if [ -n "$(govc vm.info "$name" 2>/dev/null)" ]; then
    echo "  ya existe -- se omite (borra la VM primero si quieres recrearla)"
    return
  fi

  echo "  clonando disco vía SSH (vmkfstools -i, standalone ESXi no soporta CloneVM_Task)..."
  esxi_ssh "
    set -e
    mkdir -p /vmfs/volumes/${DATASTORE}/${name}
    vmkfstools -i /vmfs/volumes/${DATASTORE}/${source_vm}/${source_vm}.vmdk -d thin /vmfs/volumes/${DATASTORE}/${name}/${name}.vmdk
    cp /vmfs/volumes/${DATASTORE}/${source_vm}/${source_vm}.vmx /vmfs/volumes/${DATASTORE}/${name}/${name}.vmx
    sed -i 's/${source_vm}/${name}/g' /vmfs/volumes/${DATASTORE}/${name}/${name}.vmx
    sed -i '/^uuid\\.\\|^vc\\.uuid/d' /vmfs/volumes/${DATASTORE}/${name}/${name}.vmx
    echo 'answer.msg.uuid.altered = \"I copied it\"' >> /vmfs/volumes/${DATASTORE}/${name}/${name}.vmx
  "
  govc vm.register "${name}/${name}.vmx"
  govc vm.change -vm "$name" -c "$vcpu" -m "$ram_mb"
  govc vm.disk.change -vm "$name" -disk.name disk-1000-0 -size "${disk_gb}G" 2>/dev/null \
    || echo "  (aviso: no se pudo redimensionar el disco automaticamente -- ajustalo a mano si hace falta)"

  # Networking: the clone inherits the template's single NIC on whatever
  # network it was built against -- remove it and add exactly the NICs
  # topology.yaml declares, in order, so ens160/ens161/... numbering
  # matches what render_topology.py assumed when writing netplan.
  local existing_nics
  existing_nics="$(govc device.ls -vm "$name" | awk '/^ethernet-/{print $1}')"
  for nic in $existing_nics; do
    govc device.remove -vm "$name" "$nic"
  done
  python3 -c "
import json, sys
meta = json.loads(sys.argv[1])['$name']
for i in meta['interfaces']:
    print(i['portgroup'])
" "$VM_META_JSON" | while read -r portgroup; do
    govc vm.network.add -vm "$name" -net "$portgroup" -net.adapter vmxnet3
  done

  # cloud-init (Ubuntu/Debian) via VMware guestinfo NoCloud datasource --
  # no HTTP server needed at deploy time, unlike Packer's own build-time
  # datasource.
  if [ "$os_family" = "ubuntu" ] || [ "$os_family" = "debian" ]; then
    local ud_file="${CLOUD_INIT_DIR}/${name}/user-data"
    local md_file="${CLOUD_INIT_DIR}/${name}/meta-data"
    if [ -f "$ud_file" ]; then
      govc vm.change -vm "$name" \
        -e guestinfo.userdata="$(base64 < "$ud_file" | tr -d '\n')" \
        -e guestinfo.userdata.encoding="base64" \
        -e guestinfo.metadata="$(base64 < "$md_file" | tr -d '\n')" \
        -e guestinfo.metadata.encoding="base64"
      echo "  cloud-init inyectado desde ${ud_file}"
    else
      echo "  AVISO: no se encontro ${ud_file} -- corre render_topology.py primero"
    fi
  elif [ "$os_family" = "alpine" ]; then
    echo "  Alpine: tras encender, aplica hostname+red a mano por la CONSOLA WEB"
    echo "          (no por SSH -- el clon aun tiene la IP/hostname del template,"
    echo "          y no hay DHCP en las VLANs nuevas). Ver:"
    echo "          ${ALPINE_DIR}/${name}/apply.sh -- pega su contenido en la consola."
  fi

  govc vm.power -on "$name"
  echo "  [OK] $name encendida"
}

{
  read -r _header
  while IFS=, read -r name template vcpu ram_mb disk_gb; do
    [ -z "$name" ] && continue
    if [ "${#FILTER[@]}" -gt 0 ]; then
      match=0
      for f in "${FILTER[@]}"; do [ "$f" = "$name" ] && match=1; done
      [ "$match" -eq 0 ] && continue
    fi
    deploy_one "$name" "$template" "$vcpu" "$ram_mb" "$disk_gb"
  done
} < "$VMS_CSV"

echo ""
echo "Listo. Para cada VM Alpine, aplica generated/alpine/<vm>/apply.sh por la"
echo "consola web (no SSH) y luego corre:"
echo "  ansible-playbook -i ../generated/ansible/inventory.ini ../ansible/site.yml"
