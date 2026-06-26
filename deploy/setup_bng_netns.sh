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
ACCESS_DHCP_RANGE_START="10.60.0.10"
ACCESS_DHCP_RANGE_END="10.60.0.200"
ACCESS_PEER_ADDR="10.60.0.1/24"
DNSMASQ_CONF="/etc/dnsmasq.d/bng-access.conf"
DNSMASQ_PIDFILE="/run/dnsmasq-bng-access.pid"

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
  if [ -f "$DNSMASQ_PIDFILE" ]; then
    sudo kill "$(cat "$DNSMASQ_PIDFILE")" 2>/dev/null || true
    sudo rm -f "$DNSMASQ_PIDFILE"
  fi
  sudo rm -f "$DNSMASQ_CONF"
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

echo "== 3. dnsmasq en ${ACCESS_PEER} (DHCP para sesiones IPoE) =="

if [ "$CHECK_ONLY" -eq 1 ]; then
  command -v dnsmasq >/dev/null 2>&1 && ok "dnsmasq instalado" || warn "dnsmasq no instalado -- corre sin --check-only"
  [ -f "$DNSMASQ_PIDFILE" ] && ok "dnsmasq de acceso corriendo" || warn "dnsmasq de acceso no está corriendo"
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

  sudo tee "$DNSMASQ_CONF" >/dev/null <<EOF
interface=${ACCESS_PEER}
bind-interfaces
except-interface=lo
dhcp-range=${ACCESS_DHCP_RANGE_START},${ACCESS_DHCP_RANGE_END},255.255.255.0,12h
EOF

  if [ -f "$DNSMASQ_PIDFILE" ] && sudo kill -0 "$(cat "$DNSMASQ_PIDFILE")" 2>/dev/null; then
    sudo kill "$(cat "$DNSMASQ_PIDFILE")"
    sleep 0.5
  fi
  sudo dnsmasq --conf-file="$DNSMASQ_CONF" --pid-file="$DNSMASQ_PIDFILE" --no-daemon &
  disown
  sleep 0.5
  if [ -f "$DNSMASQ_PIDFILE" ] || pgrep -f "dnsmasq.*${ACCESS_PEER}" >/dev/null 2>&1; then
    ok "dnsmasq corriendo en ${ACCESS_PEER} (rango ${ACCESS_DHCP_RANGE_START}-${ACCESS_DHCP_RANGE_END})"
  else
    warn "dnsmasq pudo no haber arrancado -- revisa manualmente (journalctl, o corre el comando sin --no-daemon)"
  fi
fi

echo ""
echo "*** Red lista para BNGBlaster:"
echo "    acceso : ${ACCESS_IF} (BNGBlaster) <-> ${ACCESS_PEER} (dnsmasq, ${ACCESS_PEER_ADDR})"
echo "    red    : ${NETWORK_IF} (BNGBlaster) <-> ${NETWORK_PEER} (gateway, ${NETWORK_PEER_ADDR})"
echo "    Siguiente paso: ./deploy/run_bng_scenario.sh <escenario>"
