#!/usr/bin/env bash
#
# Idempotent installer for the BGP Peering domain's toolchain on Ubuntu:
#   - FRR (bgpd + zebra)  -- the router r1 runs, receives/installs
#     announced routes. Installed from FRR's own APT repo (frrouting.org),
#     not Ubuntu's default one, since FlowSpec support needs a reasonably
#     recent FRR (8.x+) that older distro-packaged versions may not have.
#   - exabgp              -- the BGP speaker mitigation/peering_backend.py
#     talks to over its FIFO API; exabgp holds the actual session to r1.
#   - softflowd + nfdump   -- ingress flow telemetry: softflowd sniffs
#     r1's external interface and exports NetFlow/IPFIX to nfcapd (part
#     of the nfdump suite), which collectors/peering_flow_collector.py
#     reads via `nfdump -o csv`.
#
# This script installs and enables the toolchain; it does NOT configure
# the actual BGP session (peer IPs), FlowSpec address-family, or which
# interface softflowd/nfcapd should watch -- those are the deployment
# decisions the docs/peering-plan.md §2 spike works out for this
# specific topology (r1's real interface names / addressing).
#
# Usage:
#   ./deploy/install_bgp_peering.sh                 # install everything
#   ./deploy/install_bgp_peering.sh --check-only     # validate only, never install
#   ./deploy/install_bgp_peering.sh --skip-frr-repo  # use Ubuntu's own frr package
#                                                     # instead of frrouting.org's repo

set -euo pipefail

CHECK_ONLY=0
SKIP_FRR_REPO=0

while [ $# -gt 0 ]; do
  case "$1" in
    --check-only) CHECK_ONLY=1; shift ;;
    --skip-frr-repo) SKIP_FRR_REPO=1; shift ;;
    -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1" >&2; }
fail() { echo "  [FAIL] $1" >&2; exit 1; }

if [ "$(uname -s)" != "Linux" ]; then
  fail "Este toolchain solo corre en Linux -- este script debe correr en la VM Ubuntu, no aquí."
fi

# ---------------------------------------------------------------------
# 1. FRR (bgpd + zebra)
# ---------------------------------------------------------------------
echo "== 1. FRR (bgpd + zebra) =="

if [ "$CHECK_ONLY" -eq 1 ]; then
  dpkg -s frr >/dev/null 2>&1 && ok "paquete frr presente" || warn "paquete frr ausente"
  command -v vtysh >/dev/null 2>&1 && ok "vtysh en PATH ($(vtysh --version 2>&1 | head -1))" || warn "vtysh no encontrado"
else
  if dpkg -s frr >/dev/null 2>&1; then
    ok "frr ya instalado ($(dpkg -s frr | awk -F': ' '/^Version/{print $2}'))"
  elif [ "$SKIP_FRR_REPO" -eq 1 ]; then
    warn "usando el paquete frr de los repos de Ubuntu (puede no soportar FlowSpec) -- ver --skip-frr-repo"
    sudo apt-get update -qq
    sudo apt-get install -y -qq frr frr-pythontools
    ok "frr instalado desde los repos de Ubuntu"
  else
    # FRR's official repo -- see https://deb.frrouting.org/. Pulls a
    # current release rather than whatever Ubuntu's own repo happens to
    # carry, since FlowSpec support is a relatively recent addition.
    curl -fsSL https://deb.frrouting.org/frr/keys.gpg | sudo tee /usr/share/keyrings/frrouting.gpg >/dev/null
    FRRVER="frr-stable"
    echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr $(lsb_release -s -c) ${FRRVER}" \
      | sudo tee /etc/apt/sources.list.d/frr.list >/dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq frr frr-pythontools
    ok "frr instalado desde deb.frrouting.org ($(dpkg -s frr | awk -F': ' '/^Version/{print $2}'))"
  fi

  # bgpd ships disabled by default on Debian/Ubuntu packages -- FRR
  # itself will refuse to start it until this is flipped on.
  if grep -q '^bgpd=no' /etc/frr/daemons 2>/dev/null; then
    sudo sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons
    ok "bgpd habilitado en /etc/frr/daemons"
  elif grep -q '^bgpd=yes' /etc/frr/daemons 2>/dev/null; then
    ok "bgpd ya habilitado en /etc/frr/daemons"
  else
    warn "/etc/frr/daemons no tiene una línea bgpd= reconocible -- revisar manualmente"
  fi

  sudo systemctl enable frr >/dev/null 2>&1 || warn "no se pudo habilitar el servicio frr (systemd no disponible?)"
fi

# ---------------------------------------------------------------------
# 2. exabgp
# ---------------------------------------------------------------------
echo "== 2. exabgp =="

if [ "$CHECK_ONLY" -eq 1 ]; then
  command -v exabgp >/dev/null 2>&1 && ok "exabgp en PATH ($(exabgp --version 2>&1 | head -1))" || warn "exabgp ausente"
else
  if command -v exabgp >/dev/null 2>&1; then
    ok "exabgp ya instalado ($(exabgp --version 2>&1 | head -1))"
  else
    # pip, not apt -- exabgp isn't consistently packaged across Ubuntu
    # releases, while the PyPI package is the project's own primary
    # distribution channel and stays current.
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3-pip
    sudo pip3 install --break-system-packages exabgp 2>/dev/null \
      || sudo pip3 install exabgp
    ok "exabgp instalado vía pip ($(exabgp --version 2>&1 | head -1))"
  fi

  # mitigation/peering_backend.py writes to PEERING_EXABGP_FIFO
  # (config/settings.py) -- exabgp's own `api` process section is what
  # actually creates the FIFO when it starts, but the parent directory
  # needs to exist with permissions the controller process can write
  # under, ahead of that.
  sudo mkdir -p /run/exabgp
  sudo chmod 1777 /run/exabgp
  ok "/run/exabgp preparado (exabgp crea el FIFO en sí al arrancar)"
fi

# ---------------------------------------------------------------------
# 3. softflowd + nfdump (nfcapd/nfdump)
# ---------------------------------------------------------------------
echo "== 3. softflowd + nfdump =="

if [ "$CHECK_ONLY" -eq 1 ]; then
  dpkg -s softflowd >/dev/null 2>&1 && ok "softflowd presente" || warn "softflowd ausente"
  command -v nfcapd >/dev/null 2>&1 && ok "nfcapd en PATH" || warn "nfcapd no encontrado"
  command -v nfdump >/dev/null 2>&1 && ok "nfdump en PATH ($(nfdump -V 2>&1 | head -1))" || warn "nfdump no encontrado"
else
  sudo apt-get update -qq
  sudo apt-get install -y -qq softflowd nfdump
  ok "softflowd y nfdump instalados"

  # collectors/peering_flow_collector.py's default PEERING_NFCAPD_DIR
  # (config/settings.py) -- nfcapd writes its rotated capture files
  # here; the collector only ever reads, never writes, to this path.
  sudo mkdir -p /var/cache/nfcapd/r1
  sudo chmod 755 /var/cache/nfcapd/r1
  ok "/var/cache/nfcapd/r1 preparado"
fi

# ---------------------------------------------------------------------
echo
echo "Instalación completa. Pendiente (docs/peering-plan.md §2, spike de FlowSpec):"
echo "  - Configurar la sesión BGP real entre exabgp y r1 (FRR) -- IPs/ASN de este testbed."
echo "  - Habilitar 'address-family ipv4 flowspec' en bgpd y confirmar que"
echo "    FRR instala una regla real en nftables/iptables, no solo la ruta BGP."
echo "  - Apuntar softflowd a la interfaz externa real de r1 y confirmar que"
echo "    nfcapd empieza a rotar archivos en /var/cache/nfcapd/r1."
echo "  - Configurar el proceso 'api' de exabgp para leer del FIFO en /run/exabgp"
echo "    (PEERING_EXABGP_FIFO en config/settings.py)."
