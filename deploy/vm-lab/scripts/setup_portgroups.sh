#!/usr/bin/env bash
#
# setup_portgroups.sh -- creates/updates every ESXi portgroup topology.yaml's
# `networks:` block requires, with the correct security policy
# (promiscuous mode / forged transmits / MAC changes) already applied.
#
# Written after a real run found this the hard way: 3 new portgroups
# (VLAN-BACKBONE-MOBILE/FIXED/PEERING, added for the VLAN_BACKBONE work)
# were created via `govc host.portgroup.add` with ESXi's own default
# security policy (promiscuous mode OFF) -- every ping across pe's bridge
# on those 3 links failed with "Destination Host Unreachable" (looks
# exactly like a routing bug, isn't one: ARP for the far side of the
# bridge never resolves at all without promiscuous mode, since the vSwitch
# itself drops frames not addressed to the receiving vNIC's own MAC before
# OVS inside `pe` ever sees them). ENT_LAN/ENT_DC/BB_ACCESS already needed
# this for the same reason (macvlan / pe's own 2-port bridge) -- this
# script generalizes it via topology.yaml's own `promiscuous: true` field
# instead of hardcoding a list of names here, so the NEXT new bridged/
# macvlan network doesn't require rediscovering this by hand.
#
# VLAN IDs: this script does NOT choose them -- topology.yaml has no VLAN
# ID field at all (portgroup NAME is the only thing every other script
# keys on). If a portgroup doesn't exist yet, this picks the next unused
# VLAN ID above the highest one currently in use on the vSwitch (so it
# keeps extending this lab's own 800+ range without needing the ID typed
# in by hand) -- re-running this script never changes an EXISTING
# portgroup's VLAN ID, only its security policy, so it's always safe to
# re-run.
#
# Idempotent: safe to re-run any time topology.yaml's `networks:` block
# changes (a new network added, or an existing one's `promiscuous` flag
# flipped) -- existing portgroups get their security policy updated in
# place, never recreated.
#
# Prerequisites: same as deploy_govc.sh (govc installed, GOVC_URL/
# GOVC_INSECURE/GOVC_DATASTORE exported). Does NOT need ESXI_HOST/
# ESXI_SSH_PASSWORD -- unlike deploy_govc.sh's VM cloning, portgroup
# management is a real vSphere API operation, no SSH-to-the-host-shell
# workaround needed here.
#
# Usage:
#   export GOVC_URL="https://192.168.18.135/sdk"
#   export GOVC_USERNAME=root GOVC_PASSWORD='...' GOVC_INSECURE=1
#   ./setup_portgroups.sh                # create/update every portgroup
#   ./setup_portgroups.sh --dry-run      # print what would change, no writes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
TOPOLOGY_YAML="${LAB_DIR}/topology.yaml"
VSWITCH="${VSWITCH_NAME:-vSwitch0}"
DRY_RUN=false
[ "${1:-}" = "--dry-run" ] && DRY_RUN=true

command -v govc >/dev/null 2>&1 || { echo "ERROR: govc no está en PATH -- https://github.com/vmware/govmomi/releases" >&2; exit 1; }
[ -f "$TOPOLOGY_YAML" ] || { echo "ERROR: $TOPOLOGY_YAML no existe" >&2; exit 1; }

# Every portgroup name + promiscuous flag from topology.yaml, one per line:
# "NAME\tPROMISCUOUS" (PROMISCUOUS is the literal string "true" or "false").
NETWORKS_TSV="$(python3 - "$TOPOLOGY_YAML" <<'PYEOF'
import sys, yaml
t = yaml.safe_load(open(sys.argv[1]))
for name, net in t["networks"].items():
    print(f"{net['portgroup']}\t{bool(net.get('promiscuous', False))}")
PYEOF
)"

EXISTING="$(govc host.portgroup.info 2>/dev/null | awk '
  /^Name:/ {name=$2}
  /^VLAN ID:/ {print name, $3}
')"

highest_vlan() {
  echo "$EXISTING" | awk '{print $2}' | sort -n | tail -1
}

while IFS=$'\t' read -r pg_name promiscuous; do
  [ -z "$pg_name" ] && continue
  current_vlan="$(echo "$EXISTING" | awk -v n="$pg_name" '$1==n {print $2}')"

  if [ -z "$current_vlan" ]; then
    next_vlan=$(( $(highest_vlan) + 1 ))
    echo "== $pg_name: no existe, creando con VLAN $next_vlan =="
    if ! $DRY_RUN; then
      govc host.portgroup.add -vswitch "$VSWITCH" -vlan "$next_vlan" "$pg_name"
      EXISTING="$(printf '%s\n%s %s\n' "$EXISTING" "$pg_name" "$next_vlan")"
    fi
  else
    echo "== $pg_name: ya existe (VLAN $current_vlan) =="
  fi

  echo "   promiscuous=${promiscuous}, forged-transmits=${promiscuous}, mac-changes=${promiscuous}"
  if ! $DRY_RUN; then
    if [ "$promiscuous" = "True" ]; then
      govc host.portgroup.change -allow-promiscuous -forged-transmits -mac-changes "$pg_name"
    else
      govc host.portgroup.change -allow-promiscuous=false -forged-transmits=false -mac-changes=false "$pg_name"
    fi
  fi
done <<< "$NETWORKS_TSV"

echo
echo "Listo. Verificar con: govc host.portgroup.info | grep -A6 VLAN-"
