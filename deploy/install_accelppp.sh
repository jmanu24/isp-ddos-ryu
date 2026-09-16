#!/usr/bin/env bash
#
# Idempotent installer for accel-ppp (github.com/accel-ppp/accel-ppp), the
# real open-source BRAS/BNG this project uses to replace BNGBlaster in the
# Broadband domain's distributed VM lab (see bngblaster_broadband_pipeline_
# status memory for why: BNGBlaster's sendto() succeeded but the frame was
# invisible to every external observer on this lab, an unresolved bug).
#
# accel-ppp has no precompiled .deb releases the way rtbrick/bngblaster does
# (see deploy/install_bngblaster.sh) -- every documented install path is a
# source build via cmake, on Debian/Ubuntu/CentOS. This mirrors that
# script's own idempotent/--check-only/--version shape, just git-clone+cmake
# instead of downloading a release asset.
#
# NOT yet verified against a real run (unlike install_bngblaster.sh, which
# accumulated several real-run fixes) -- this Mac had no route to the lab's
# MGMT network when this was written. Flags/deps below are accel-ppp's own
# documented build requirements; expect the first real run to need fixes,
# same as every other piece of this lab did.
#
# Usage:
#   ./deploy/install_accelppp.sh                    # installs the default branch
#   ./deploy/install_accelppp.sh --version 1.13.0    # installs a specific tag
#   ./deploy/install_accelppp.sh --check-only        # validate only, never install

set -euo pipefail

VERSION=""
CHECK_ONLY=0
REPO_URL="https://github.com/accel-ppp/accel-ppp.git"
BUILD_DIR="/opt/accel-ppp-src"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --check-only) CHECK_ONLY=1; shift ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1" >&2; }
fail() { echo "  [FAIL] $1" >&2; exit 1; }

if [ "$(uname -s)" != "Linux" ]; then
  fail "accel-ppp solo corre en Linux -- este script debe correr en la VM bng, no aquí."
fi

echo "== 1. Dependencias de build =="

# libpcre2-dev, NOT libpcre3-dev -- confirmed on a real run: accel-ppp's
# own CMakeLists.txt requires PCRE2 specifically ("Required libpcre not
# found. Install libpcre2-dev and run cmake again"), the legacy PCRE1
# libpcre3-dev doesn't satisfy it despite the similar package name.
BUILD_PKGS="build-essential cmake git pkg-config libssl-dev liblua5.1-0-dev libpcre2-dev libjson-c-dev linux-headers-$(uname -r)"

if [ "$CHECK_ONLY" -eq 1 ]; then
  for pkg in $BUILD_PKGS; do
    dpkg -s "$pkg" >/dev/null 2>&1 && ok "$pkg presente" || warn "$pkg ausente"
  done
else
  sudo apt-get update -qq
  sudo apt-get install -y -qq $BUILD_PKGS
  ok "dependencias de build instaladas"
fi

echo "== 2. Binario accel-pppd =="

if command -v accel-pppd >/dev/null 2>&1; then
  ok "accel-pppd ya está instalado en $(command -v accel-pppd)"
else
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "accel-pppd no está instalado -- corre sin --check-only"
  fi

  if [ -d "$BUILD_DIR/.git" ]; then
    ok "código fuente ya clonado en $BUILD_DIR"
    sudo git -C "$BUILD_DIR" fetch --tags --quiet
  else
    echo "  -> clonando ${REPO_URL}..."
    sudo git clone --quiet "$REPO_URL" "$BUILD_DIR"
  fi

  if [ -n "$VERSION" ]; then
    echo "  -> checkout ${VERSION}"
    sudo git -C "$BUILD_DIR" checkout --quiet "$VERSION"
  fi

  sudo rm -rf "$BUILD_DIR/build"
  sudo mkdir -p "$BUILD_DIR/build"

  # -DBUILD_IPOE_DRIVER=FALSE / -DBUILD_VLAN_MON_DRIVER=FALSE: skip the
  # optional in-kernel fast-path modules (need KDIR matching a full kernel
  # build tree, not just headers) -- accel-ppp's userspace ipoe module
  # works without them, just without that extra fast path. Fine for a lab.
  # -DRADIUS=TRUE: this project's whole reason for choosing accel-ppp --
  # real RADIUS auth/accounting against FreeRADIUS (roles/bng's own
  # tasks configure the FreeRADIUS side).
  (
    cd "$BUILD_DIR/build"
    sudo cmake \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DBUILD_IPOE_DRIVER=FALSE \
      -DBUILD_VLAN_MON_DRIVER=FALSE \
      -DBUILD_PPTP_DRIVER=FALSE \
      -DLUA=TRUE \
      -DRADIUS=TRUE \
      -DSHAPER=TRUE \
      -DNETSNMP=FALSE \
      ..
    sudo make -j"$(nproc)"
    sudo make install
  )

  if command -v accel-pppd >/dev/null 2>&1; then
    ok "accel-pppd instalado en $(command -v accel-pppd)"
  else
    fail "el build terminó pero accel-pppd no aparece en PATH -- revisa la salida de cmake/make arriba"
  fi
fi

echo ""
echo "*** accel-ppp listo: $(command -v accel-pppd)"
echo "    accel-cmd (CLI de control): $(command -v accel-cmd || echo 'no encontrado en PATH')"
echo "    Siguiente paso: deploy/vm-lab/ansible/roles/bng despliega /etc/accel-ppp.conf y el unit systemd"
