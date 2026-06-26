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

  ARCH="$(dpkg --print-architecture)"
  if [ -n "$VERSION" ]; then
    DEB_URL="https://github.com/rtbrick/bngblaster/releases/download/${VERSION}/bngblaster-${VERSION}-${ARCH}.deb"
  else
    # "latest" redirect -- avoids hardcoding a version this script will
    # silently go stale against.
    DEB_URL="https://github.com/rtbrick/bngblaster/releases/latest/download/bngblaster-${ARCH}.deb"
  fi

  TMP_DEB="$(mktemp --suffix=.deb)"
  echo "  -> descargando ${DEB_URL}..."
  if ! curl -fsSL "$DEB_URL" -o "$TMP_DEB"; then
    rm -f "$TMP_DEB"
    fail "no se pudo descargar el .deb -- revisa la versión/arquitectura en https://github.com/rtbrick/bngblaster/releases"
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
