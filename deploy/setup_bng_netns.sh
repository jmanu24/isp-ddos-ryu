#!/usr/bin/env bash
#
# Idempotent setup of the two veth pairs BNGBlaster's config
# (simulation/bng_config.py's default veth-a/veth-n interface names)
# needs to exist as real, "up" Linux interfaces before bngblaster can
# bind raw sockets to them.
#
#   veth-a <-> veth-a-peer   (access side: PPPoE/IPoE sessions)
#   veth-n <-> veth-n-peer   (network side: BNGBlaster's own IP/gateway)
#
# veth-n-peer gets the gateway address simulation/bng_config.py's
# network_gateway points BNGBlaster at (10.50.0.1/24 by default), so ARP
# for it resolves and outbound attack/baseline traffic doesn't
# immediately get dropped for lack of an L2 neighbor.
#
# veth-a-peer needs a DHCP server answering IPoE sessions' DHCP requests
# for BNGBlaster's sessions to actually come up (the "dhcp": {"enable":
# true} block in bng_config.py's config makes each session a DHCP
# CLIENT -- something has to answer it). Uses dnsmasq if present; if
# it's not installed this script installs+configures a minimal instance
# scoped to veth-a-peer only (not a system-wide DHCP server).
#
# BNGBlaster assigns each IPoE session its OWN outer VLAN tag out of
# simulation/bng_config.py's outer-vlan-min/max range (1..session_count)
# -- confirmed on a real run: a 0/0 (untagged) range only fits ONE
# session ("VLAN ranges exhausted!" trying to create an 8-session
# config). So this script creates one 802.1Q sub-interface per VLAN ID
# on veth-a-peer (veth-a-peer.1 .. veth-a-peer.MAX_VLAN), each its own
# /24, and dnsmasq listens + hands out leases on every one of them --
# otherwise a session's VLAN-tagged DHCPDISCOVER never reaches a plain,
# VLAN-unaware listener on veth-a-peer itself.
#
# NOTE: this interface/DHCP layout is this script's own best-effort
# design, not something copied from a confirmed BNGBlaster reference
# setup (see bng_socket.py's docstring on what in this pipeline is
# unverified) -- if session establishment fails on a real run, check
# dnsmasq's log (journalctl -u dnsmasq, or the path this script prints)
# before assuming the bngblaster config itself is wrong.
#
# Usage:
#   sudo ./deploy/setup_bng_netns.sh
#   sudo ./deploy/setup_bng_netns.sh --teardown
#   ./deploy/setup_bng_netns.sh --check-only

set -euo pipefail

ACCESS_IF="veth-a"
ACCESS_PEER="veth-a-peer"
NETWORK_IF="veth-n"
NETWORK_PEER="veth-n-peer"
NETWORK_PEER_ADDR="10.50.0.1/24"
ACCESS_PEER_ADDR="10.60.0.1/24"
DNSMASQ_CONF="/etc/dnsmasq.d/bng-access.conf"
# Must stay >= the largest session_count any scenario in
# simulation/bng_config.py's SCENARIOS uses (currently 8, for
# distributed_syn_flood/low_and_slow) -- one VLAN sub-interface gets
# created per ID in 1..MAX_VLAN, each its own /24 (10.61.<vid>.0/24).
MAX_VLAN=8
# dnsmasq's dhcp-hostsfile -- telemetry/broadband_adapter.py appends
# "<mac>,ignore" lines here on a block (dnsmasq then refuses to offer
# that MAC a lease at all) and removes them on unblock, then SIGHUPs
# dnsmasq to reload without restarting it. World-writable (0666) since
# the controller process that edits it normally runs as a regular
# user, not root -- same throwaway-local-simulation justification as
# the control socket's own chmod (see bng_traffic_simulator.py).
DHCP_BLACKLIST_PATH="/tmp/bng_dhcp_blacklist.hosts"

TEARDOWN=0
CHECK_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --teardown) TEARDOWN=1; shift ;;
    --check-only) CHECK_ONLY=1; shift ;;
    -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1" >&2; }
fail() { echo "  [FAIL] $1" >&2; exit 1; }

if [ "$(uname -s)" != "Linux" ]; then
  fail "veth solo existe en Linux -- corre esto en la VM Ubuntu, no aquí."
fi

iface_exists() { ip link show "$1" >/dev/null 2>&1; }

if [ "$TEARDOWN" -eq 1 ]; then
  echo "== Desmontando interfaces y dnsmasq de acceso =="
  # Matched by conf-file path in its own argv, not a pid-file -- dnsmasq
  # under --no-daemon doesn't reliably write the --pid-file path (the
  # pidfile is meant for a daemonized parent to manage; confirmed on a
  # real run: the file never appeared even though dnsmasq itself logged
  # "started" successfully), so a pidfile-based kill silently killed
  # nothing.
  sudo pkill -f "dnsmasq.*${DNSMASQ_CONF}" 2>/dev/null && ok "dnsmasq de acceso detenido" || ok "dnsmasq de acceso no estaba corriendo"
  sudo rm -f "$DNSMASQ_CONF" "$DHCP_BLACKLIST_PATH"
  iface_exists "$ACCESS_IF" && sudo ip link del "$ACCESS_IF" && ok "${ACCESS_IF}/${ACCESS_PEER} eliminados"
  iface_exists "$NETWORK_IF" && sudo ip link del "$NETWORK_IF" && ok "${NETWORK_IF}/${NETWORK_PEER} eliminados"
  exit 0
fi

# disable_ipv6 + flush -- the kernel auto-assigns an IPv6 link-local
# address (fe80::...) to any interface the moment it goes up, and
# BNGBlaster logged exactly that as a real blocker on a live run
# ("Warning: IP address fe80::... on interface veth-n is conflicting!"):
# it wants exclusive raw-socket control of veth-n/veth-a, no
# kernel-managed address at all, not even an automatic IPv6 one
# ("Interfaces must not have an IP address configured in the host OS!").
# Applied unconditionally (not just at interface-creation time) so a
# rerun against interfaces a PREVIOUS version of this script already
# created also gets fixed, not just brand-new ones. Only applied to
# BNGBlaster's own sides -- the *-peer ends keep their IPv4 addresses,
# those need to stay reachable.
disable_ipv6() {
  sudo sysctl -qw "net.ipv6.conf.$1.disable_ipv6=1"
  sudo ip -6 addr flush dev "$1" 2>/dev/null || true
}

echo "== 1. Par veth de red (${NETWORK_IF} <-> ${NETWORK_PEER}) =="

if iface_exists "$NETWORK_IF"; then
  ok "${NETWORK_IF} ya existe"
else
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "${NETWORK_IF} no existe -- corre sin --check-only"
  fi
  sudo ip link add "$NETWORK_IF" type veth peer name "$NETWORK_PEER"
  sudo ip link set "$NETWORK_IF" up
  sudo ip link set "$NETWORK_PEER" up
  sudo ip addr add "$NETWORK_PEER_ADDR" dev "$NETWORK_PEER" 2>/dev/null || true
  ok "${NETWORK_IF}/${NETWORK_PEER} creados (${NETWORK_PEER} = ${NETWORK_PEER_ADDR})"
fi
disable_ipv6 "$NETWORK_IF"

echo "== 2. Par veth de acceso (${ACCESS_IF} <-> ${ACCESS_PEER}) =="

if iface_exists "$ACCESS_IF"; then
  ok "${ACCESS_IF} ya existe"
else
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "${ACCESS_IF} no existe -- corre sin --check-only"
  fi
  sudo ip link add "$ACCESS_IF" type veth peer name "$ACCESS_PEER"
  sudo ip link set "$ACCESS_IF" up
  sudo ip link set "$ACCESS_PEER" up
  sudo ip addr add "$ACCESS_PEER_ADDR" dev "$ACCESS_PEER" 2>/dev/null || true
  ok "${ACCESS_IF}/${ACCESS_PEER} creados (${ACCESS_PEER} = ${ACCESS_PEER_ADDR})"
fi
disable_ipv6 "$ACCESS_IF"
ok "IPv6 deshabilitado en ${NETWORK_IF}/${ACCESS_IF}"

echo "== 3. Sub-interfaces VLAN en ${ACCESS_PEER} (1 por VLAN ID, para DHCP por sesión) =="

sudo modprobe 8021q 2>/dev/null || true

for VID in $(seq 1 "$MAX_VLAN"); do
  SUBIF="${ACCESS_PEER}.${VID}"
  if iface_exists "$SUBIF"; then
    ok "${SUBIF} ya existe"
  else
    if [ "$CHECK_ONLY" -eq 1 ]; then
      fail "${SUBIF} no existe -- corre sin --check-only"
    fi
    sudo ip link add link "$ACCESS_PEER" name "$SUBIF" type vlan id "$VID"
    sudo ip link set "$SUBIF" up
    sudo ip addr add "10.61.${VID}.1/24" dev "$SUBIF" 2>/dev/null || true
  fi
done
ok "${MAX_VLAN} sub-interfaces VLAN listas en ${ACCESS_PEER} (10.61.1.1/24 .. 10.61.${MAX_VLAN}.1/24)"

echo "== 4. dnsmasq en ${ACCESS_PEER} (DHCP por VLAN para sesiones IPoE) =="

dnsmasq_running() { pgrep -f "dnsmasq.*${DNSMASQ_CONF}" >/dev/null 2>&1; }

if [ "$CHECK_ONLY" -eq 1 ]; then
  command -v dnsmasq >/dev/null 2>&1 && ok "dnsmasq instalado" || warn "dnsmasq no instalado -- corre sin --check-only"
  dnsmasq_running && ok "dnsmasq de acceso corriendo" || warn "dnsmasq de acceso no está corriendo"
else
  if ! command -v dnsmasq >/dev/null 2>&1; then
    echo "  -> instalando dnsmasq..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq dnsmasq
  fi

  # `command -v dnsmasq` can already be true from a DIFFERENT package
  # (e.g. dnsmasq-base, pulled in by NetworkManager/libvirt) that never
  # creates /etc/dnsmasq.d -- confirmed on a real run: dnsmasq was
  # already present, the install step above was skipped, and the `tee`
  # below failed outright ("No such file or directory") instead of
  # silently doing nothing. Created unconditionally rather than only
  # inside the "not installed" branch.
  sudo mkdir -p "$(dirname "$DNSMASQ_CONF")"
  sudo touch "$DHCP_BLACKLIST_PATH"
  sudo chmod 0666 "$DHCP_BLACKLIST_PATH"

  {
    echo "bind-interfaces"
    echo "except-interface=lo"
    echo "dhcp-hostsfile=${DHCP_BLACKLIST_PATH}"
    # One interface+dhcp-range pair per VLAN sub-interface -- dnsmasq
    # serves a distinct lease pool per L2 segment, matching one
    # BNGBlaster session's VLAN to its own /24 instead of every VLAN
    # competing for the same single range on the (VLAN-unaware) parent
    # ${ACCESS_PEER} interface.
    for VID in $(seq 1 "$MAX_VLAN"); do
      echo "interface=${ACCESS_PEER}.${VID}"
      echo "dhcp-range=10.61.${VID}.10,10.61.${VID}.200,255.255.255.0,12h"
    done
  } | sudo tee "$DNSMASQ_CONF" >/dev/null

  if dnsmasq_running; then
    sudo pkill -f "dnsmasq.*${DNSMASQ_CONF}"
    sleep 0.5
  fi
  sudo dnsmasq --conf-file="$DNSMASQ_CONF" --no-daemon &
  disown
  sleep 0.5
  # Matched by conf-file path, not a --pid-file -- confirmed on a real
  # run: dnsmasq logged "started" successfully and IS actually running
  # under --no-daemon, but never writes the pid-file path in that mode
  # (it's meant for a daemonized parent to manage), so the old
  # `[ -f "$DNSMASQ_PIDFILE" ]` check always reported a false [WARN]
  # even when dnsmasq was healthy.
  if dnsmasq_running; then
    ok "dnsmasq corriendo en ${MAX_VLAN} sub-interfaces VLAN de ${ACCESS_PEER}"
  else
    warn "dnsmasq no arrancó -- revisa manualmente (journalctl, o corre el comando sin --no-daemon)"
  fi
fi

echo "== 5. IP forwarding (para que el tráfico downstream de session-traffic vuelva a la sesión) =="

# BNGBlaster's session-traffic sends "downstream" packets out the
# NETWORK interface (veth-n, source 10.50.0.x) addressed to each
# session's own access-side IP (10.61.<vid>.x) -- a DIFFERENT subnet,
# reachable only if the host itself routes between them (veth-n-peer's
# 10.50.0.0/24 and veth-a-peer.<vid>'s 10.61.<vid>.0/24 are both
# directly-connected routes already; only ip_forward was missing).
# Confirmed real symptom without this: a session's reported pps ramped
# up for ~15s then the session abruptly DHCPRELEASEd and re-established
# itself, repeating in a loop -- session-streams' downstream flow's
# rx-packets stayed 0 forever (it could never actually arrive back at
# the access side), and BNGBlaster appears to consider that unhealthy
# enough to recycle the session. Without forwarding enabled, upstream-
# only scenarios may still "work" telemetry-wise (collect() only reads
# tx-pps), but the periodic flap is disruptive either way.
sudo sysctl -qw net.ipv4.ip_forward=1
ok "net.ipv4.ip_forward=1"

echo ""
echo "*** Red lista para BNGBlaster:"
echo "    acceso : ${ACCESS_IF} (BNGBlaster) <-> ${ACCESS_PEER} (dnsmasq, ${ACCESS_PEER_ADDR})"
echo "    red    : ${NETWORK_IF} (BNGBlaster) <-> ${NETWORK_PEER} (gateway, ${NETWORK_PEER_ADDR})"
echo "    Siguiente paso: ./deploy/run_bng_scenario.sh <escenario>"
