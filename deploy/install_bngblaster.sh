#!/usr/bin/env bash
#
# Idempotent installer for the real BNGBlaster binary (rtbrick/bngblaster)
# on Ubuntu/Debian, via its precompiled .deb releases -- needed by
# simulation/bng_traffic_simulator.py to actually exist on PATH.
#
# Linux-only, and only really exercised on the Ubuntu test VM (see
# bng_traffic_simulator.py's module docstring) -- BNGBlaster needs raw
# sockets, which macOS doesn't expose the same way.
#
# Usage:
#   ./deploy/install_bngblaster.sh                 # installs the latest release
#   ./deploy/install_bngblaster.sh --version 0.9.30 # installs a specific tag
#   ./deploy/install_bngblaster.sh --check-only     # validate only, never install

set -euo pipefail

VERSION=""
CHECK_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --check-only) CHECK_ONLY=1; shift ;;
    -h|--help) sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1" >&2; }
fail() { echo "  [FAIL] $1" >&2; exit 1; }

if [ "$(uname -s)" != "Linux" ]; then
  fail "BNGBlaster solo corre en Linux (sockets raw) -- este script debe correr en la VM Ubuntu, no aquí."
fi

echo "== 1. Dependencias runtime =="

# Field names vary by base image -- Ubuntu 18.04/20.04 ships libssl1.1,
# 22.04+/Debian Bookworm ships libssl3 instead (per BNGBlaster's own
# install docs). Tries the modern set first, falls back to the older one.
RUNTIME_PKGS_MODERN="libssl3 libncurses6 libjansson4"
RUNTIME_PKGS_LEGACY="libssl1.1 libncurses5 libjansson4"

if [ "$CHECK_ONLY" -eq 1 ]; then
  for pkg in $RUNTIME_PKGS_MODERN; do
    dpkg -s "$pkg" >/dev/null 2>&1 && ok "$pkg presente" || warn "$pkg ausente (puede estar cubierto por el set legacy)"
  done
else
  sudo apt-get update -qq
  if sudo apt-get install -y -qq $RUNTIME_PKGS_MODERN 2>/dev/null; then
    ok "dependencias runtime (set moderno) instaladas"
  else
    warn "set moderno no disponible, probando set legacy (Ubuntu 18.04/20.04)..."
    sudo apt-get install -y -qq $RUNTIME_PKGS_LEGACY
    ok "dependencias runtime (set legacy) instaladas"
  fi
fi

echo "== 2. Binario bngblaster =="

if command -v bngblaster >/dev/null 2>&1; then
  ok "bngblaster ya está instalado en $(command -v bngblaster)"
else
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "bngblaster no está instalado -- corre sin --check-only"
  fi

  # Asset names are "bngblaster-<version>-<os-tag>_<arch>.deb" -- NOT a
  # generic "latest/download/bngblaster-<arch>.deb" (that 404s; confirmed
  # on a real run). <os-tag> is "ubuntu-XX.YY" for Ubuntu or a Debian
  # codename (bookworm/trixie) for Debian, and recent releases don't
  # necessarily ship a build for every OS tag -- e.g. as of 0.9.36 there
  # is no ubuntu-20.04 build; 0.9.17 is the last release that has one.
  # So this queries the GitHub API for actual release assets instead of
  # guessing a URL, and walks backwards from the newest release until it
  # finds one that actually published a .deb for this OS tag.
  ARCH="$(dpkg --print-architecture)"

  # Read only the specific keys needed, instead of sourcing
  # /etc/os-release directly -- it defines its OWN "VERSION" variable
  # ("20.04.4 LTS (Focal Fossa)"), which collided with and silently
  # overwrote this script's $VERSION (the --version flag), corrupting
  # the .deb URL built below (confirmed on a real run).
  OS_ID=""
  OS_VERSION_ID=""
  OS_VERSION_CODENAME=""
  if [ -f /etc/os-release ]; then
    OS_ID="$(. /etc/os-release && echo "$ID")"
    OS_VERSION_ID="$(. /etc/os-release && echo "$VERSION_ID")"
    OS_VERSION_CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
  fi
  case "$OS_ID" in
    ubuntu) OS_TAG="ubuntu-${OS_VERSION_ID}" ;;
    debian) OS_TAG="${OS_VERSION_CODENAME:-bookworm}" ;;
    *)      OS_TAG="ubuntu-${OS_VERSION_ID:-22.04}" ;;
  esac
  ok "OS detectado: ID=${OS_ID:-?} VERSION_ID=${OS_VERSION_ID:-?} -> buscando assets *-${OS_TAG}_${ARCH}.deb"

  DEB_URL=""
  if [ -n "$VERSION" ]; then
    DEB_URL="https://github.com/rtbrick/bngblaster/releases/download/${VERSION}/bngblaster-${VERSION}-${OS_TAG}_${ARCH}.deb"
  else
    echo "  -> consultando releases en GitHub (rtbrick/bngblaster)..."
    for PAGE in 1 2 3; do
      RELEASES_JSON="$(curl -fsSL "https://api.github.com/repos/rtbrick/bngblaster/releases?per_page=100&page=${PAGE}")" || break
      [ -z "$RELEASES_JSON" ] && break
      DEB_URL="$(echo "$RELEASES_JSON" \
        | grep -o "https://github.com/rtbrick/bngblaster/releases/download/[^\"]*-${OS_TAG}_${ARCH}\.deb" \
        | head -1)"
      [ -n "$DEB_URL" ] && break
    done
  fi

  if [ -z "$DEB_URL" ]; then
    fail "no se encontró ningún release con un .deb para ${OS_TAG}_${ARCH} -- revisa manualmente https://github.com/rtbrick/bngblaster/releases y pasa --version <tag>"
  fi

  TMP_DEB="$(mktemp --suffix=.deb)"
  echo "  -> descargando ${DEB_URL}..."
  if ! curl -fsSL "$DEB_URL" -o "$TMP_DEB"; then
    rm -f "$TMP_DEB"
    fail "no se pudo descargar ${DEB_URL}"
  fi

  sudo dpkg -i "$TMP_DEB" || sudo apt-get install -f -y -qq
  rm -f "$TMP_DEB"

  if command -v bngblaster >/dev/null 2>&1; then
    ok "bngblaster instalado en $(command -v bngblaster)"
  else
    fail "el .deb se instaló pero bngblaster no aparece en PATH"
  fi
fi

echo "== 3. Capacidades de red (raw sockets sin requerir sudo en cada corrida) =="

BNG_BIN="$(command -v bngblaster || echo /usr/sbin/bngblaster)"
if [ "$CHECK_ONLY" -eq 1 ]; then
  if getcap "$BNG_BIN" 2>/dev/null | grep -q cap_net_raw; then
    ok "capabilities ya asignadas a ${BNG_BIN}"
  else
    warn "capabilities no asignadas -- corre sin --check-only, o usa 'sudo' al ejecutar bng_traffic_simulator.py"
  fi
else
  sudo setcap cap_net_raw,cap_net_admin,cap_dac_read_search+eip "$BNG_BIN" \
    && ok "capabilities asignadas a ${BNG_BIN}" \
    || warn "no se pudieron asignar capabilities -- seguirá funcionando con 'sudo'"
fi

echo ""
echo "*** BNGBlaster listo: $(bngblaster --version 2>/dev/null || echo "$BNG_BIN")"
echo "    Siguiente paso: ./deploy/setup_bng_netns.sh"
