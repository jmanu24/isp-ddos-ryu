#!/usr/bin/env bash
#
# Idempotent installer for the BGP Peering domain's toolchain on Ubuntu:
#   - flow                 -- the tool r1 runs that receives BGP FlowSpec
#     routes and installs them as real nftables rules via rtnetlink(7).
#     See docs/peering-plan.md §2: FRR's own FlowSpec-to-dataplane bridge
#     never installs the rule for real (confirmed, long-standing gap in
#     FRR mainline, FRRouting/frr#3160) -- `flow` does, confirmed with a
#     live `nft list ruleset` output. Installed from a prebuilt release
#     binary (github.com/hack3ric/flow), no Rust toolchain needed.
#   - exabgp                -- the BGP speaker mitigation/peering_backend.py
#     talks to over its FIFO API; exabgp holds the actual session to `flow`.
#   - softflowd + nfdump    -- ingress flow telemetry: softflowd sniffs
#     r1's external interface and exports NetFlow/IPFIX to nfcapd (part
#     of the nfdump suite), which collectors/peering_flow_collector.py
#     reads via `nfdump -o csv`.
#   - FRR (optional, --with-frr only) -- kept ONLY to reproduce the
#     documented negative result in deploy/spike_flowspec_frr.sh. Not
#     part of the working pipeline -- do not point mitigation/
#     peering_backend.py at it.
#
# This script installs and enables the toolchain; it does NOT configure
# the actual BGP session (peer IPs/ASNs) or which interface softflowd/
# nfcapd should watch -- those are the deployment decisions
# docs/peering-plan.md §5 works out for this specific topology (r1's
# real interface names / addressing inside Mininet).
#
# Usage:
#   ./deploy/install_bgp_peering.sh                 # install flow + exabgp + softflowd/nfdump
#   ./deploy/install_bgp_peering.sh --check-only     # validate only, never install
#   ./deploy/install_bgp_peering.sh --with-frr       # also install FRR (historical spike only)
#   ./deploy/install_bgp_peering.sh --flow-version 0.2.0  # pin a specific flow release

set -euo pipefail

CHECK_ONLY=0
WITH_FRR=0
FLOW_VERSION="0.2.0"

while [ $# -gt 0 ]; do
  case "$1" in
    --check-only) CHECK_ONLY=1; shift ;;
    --with-frr) WITH_FRR=1; shift ;;
    --flow-version) FLOW_VERSION="$2"; shift 2 ;;
    -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1" >&2; }
fail() { echo "  [FAIL] $1" >&2; exit 1; }

if [ "$(uname -s)" != "Linux" ]; then
  fail "Este toolchain solo corre en Linux -- este script debe correr en la VM Ubuntu, no aquí."
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) FLOW_ARCH="x86_64-unknown-linux-gnu" ;;
  aarch64) FLOW_ARCH="aarch64-unknown-linux-gnu" ;;
  armv7l) FLOW_ARCH="armv7-unknown-linux-gnueabihf" ;;
  *) FLOW_ARCH="" ;;
esac

# ---------------------------------------------------------------------
# 1. flow -- the real FlowSpec-to-nftables installer (see docs/peering-plan.md §2.2)
# ---------------------------------------------------------------------
echo "== 1. flow (FlowSpec -> nftables, github.com/hack3ric/flow) =="

if [ "$CHECK_ONLY" -eq 1 ]; then
  command -v flow >/dev/null 2>&1 && ok "flow en PATH ($(flow --help 2>&1 | head -1))" || warn "flow ausente"
  command -v nft >/dev/null 2>&1 && ok "nft (nftables) en PATH" || warn "nft no encontrado"
else
  if command -v flow >/dev/null 2>&1; then
    ok "flow ya instalado ($(command -v flow))"
  else
    [ -n "$FLOW_ARCH" ] || fail "arquitectura '$ARCH' sin binario precompilado de flow -- ver https://github.com/hack3ric/flow/releases"

    TMPDIR="$(mktemp -d)"
    ASSET="flow-${FLOW_VERSION}-${FLOW_ARCH}.tar.xz"
    URL="https://github.com/hack3ric/flow/releases/download/v${FLOW_VERSION}/${ASSET}"

    curl -fSL -o "${TMPDIR}/${ASSET}" "$URL"
    curl -fSL -o "${TMPDIR}/${ASSET}.sha256" "${URL}.sha256"
    # The .sha256 file lists the asset's own filename, which already
    # matches what was just downloaded (no renaming here) -- so a plain
    # `sha256sum -c` against it works without editing its contents.
    (cd "$TMPDIR" && sha256sum -c "${ASSET}.sha256")
    tar xf "${TMPDIR}/${ASSET}" -C "$TMPDIR"
    sudo install -m 755 "${TMPDIR}/flow-${FLOW_VERSION}-${FLOW_ARCH}/flow" /usr/local/bin/flow
    rm -rf "$TMPDIR"
    ok "flow ${FLOW_VERSION} instalado en /usr/local/bin/flow (checksum verificado)"
  fi

  sudo apt-get update -qq
  sudo apt-get install -y -qq nftables
  ok "nftables instalado (lo que flow usa para instalar las reglas)"

  # flow's default --run-dir is /run/flow.
  sudo mkdir -p /run/flow
  ok "/run/flow preparado"
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
  # (config/settings.py). exabgp does NOT create this FIFO itself --
  # its config needs a `process` block that runs `cat <this path>`,
  # whose stdout exabgp reads as commands (see the ExaBGP wiki's
  # "Controlling ExaBGP: using a named PIPE"). Created here so it
  # exists ahead of that config being written; harmless to pre-create
  # even though the real deployment's exabgp.conf is still pending.
  sudo mkdir -p /run/exabgp
  sudo chmod 1777 /run/exabgp
  [ -p /run/exabgp/exabgp.in ] || sudo mkfifo -m 666 /run/exabgp/exabgp.in
  ok "/run/exabgp/exabgp.in (FIFO) preparado"
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
# 4. FRR (optional -- historical spike only, NOT part of the working pipeline)
# ---------------------------------------------------------------------
if [ "$WITH_FRR" -eq 1 ]; then
  echo "== 4. FRR (--with-frr: solo para reproducir deploy/spike_flowspec_frr.sh) =="
  warn "FRR NO se usa en el pipeline real -- ver docs/peering-plan.md §2.1. Instalando solo para reproducir el spike documentado como FAIL."

  if [ "$CHECK_ONLY" -eq 1 ]; then
    dpkg -s frr >/dev/null 2>&1 && ok "paquete frr presente" || warn "paquete frr ausente"
  else
    if dpkg -s frr >/dev/null 2>&1; then
      ok "frr ya instalado ($(dpkg -s frr | awk -F': ' '/^Version/{print $2}'))"
    else
      curl -fsSL https://deb.frrouting.org/frr/keys.gpg | sudo tee /usr/share/keyrings/frrouting.gpg >/dev/null
      echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr $(lsb_release -s -c) frr-stable" \
        | sudo tee /etc/apt/sources.list.d/frr.list >/dev/null
      sudo apt-get update -qq
      sudo apt-get install -y -qq frr frr-pythontools iptables ipset
      ok "frr instalado desde deb.frrouting.org ($(dpkg -s frr | awk -F': ' '/^Version/{print $2}'))"
    fi
    if grep -q '^bgpd=no' /etc/frr/daemons 2>/dev/null; then
      sudo sed -i 's/^bgpd=no/bgpd=yes/; s/^pbrd=no/pbrd=yes/' /etc/frr/daemons
      ok "bgpd y pbrd habilitados en /etc/frr/daemons"
    fi
    sudo systemctl enable frr >/dev/null 2>&1 || true
  fi
fi

# ---------------------------------------------------------------------
echo
echo "Instalación completa. Pendiente (docs/peering-plan.md §5, integración con la topología real):"
echo "  - Arrancar 'flow' en r1 dentro de la topología Mininet (no solo en el spike aislado)."
echo "  - Configurar exabgp (mitigation/peering_backend.py) para apuntar a esa instancia de flow."
echo "  - Apuntar softflowd a la interfaz externa real de r1 y confirmar que"
echo "    nfcapd empieza a rotar archivos en /var/cache/nfcapd/r1."
echo "  - Ver deploy/spike_flowspec_flow.sh para el procedimiento ya validado end-to-end."
