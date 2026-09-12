#!/usr/bin/env bash
#
# deploy_govc.sh -- clones the 16 VMs from their golden templates directly
# onto a standalone ESXi host (no vCenter needed -- govc talks to ESXi's
# own API), sizing each per ../topology.yaml (via generated/govc/vms.csv,
# see scripts/render_topology.py) and injecting its per-VM cloud-init
# (Ubuntu/Debian) via VMware guestinfo.
#
# Prerequisites:
#   - govc installed (https://github.com/vmware/govmomi/tree/main/govc)
#   - The 3 golden templates (tpl-alpine, tpl-ubuntu-2204, tpl-debian-13)
#     already built via ../packer/*.pkr.hcl and present on the ESXi host
#   - python3 scripts/render_topology.py already run (needs generated/ to exist)
#   - GOVC_URL / GOVC_INSECURE exported, or passed via --host below
#
# Usage:
#   export GOVC_URL="https://root:PASSWORD@ESXI_HOST/sdk"
#   export GOVC_INSECURE=1
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
# exist, it does not create switches/port groups (those are a one-time,
# host-level decision this script shouldn't make for you).

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
: "${GOVC_URL:?export GOVC_URL=\"https://root:PASSWORD@ESXI_HOST/sdk\" primero}"

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

  if govc vm.info "$name" >/dev/null 2>&1; then
    echo "  ya existe -- se omite (borra la VM primero si quieres recrearla)"
    return
  fi

  govc vm.clone -vm "$source_vm" -on=false -c="$vcpu" -m="$ram_mb" -ds="$DATASTORE" "$name"
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
    echo "  Alpine: aplica ${ALPINE_DIR}/${name}/answerfile a mano tras el primer arranque"
    echo "          (scp + 'setup-alpine -f answerfile', o reconstruye desde ISO -- ver README.md)"
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
echo "Listo. Para Alpine, aplica los answerfiles pendientes y luego corre:"
echo "  ansible-playbook -i ../generated/ansible/inventory.ini ../ansible/site.yml"
