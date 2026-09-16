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

  # -DBUILD_IPOE_DRIVER=TRUE -- NOT optional in practice: confirmed on a
  # real run that accel-pppd's userspace ipoe module talks to this
  # kernel module over netlink for EVERY incoming session (not just
  # ifcfg=1's per-session interface feature) -- without it loaded, every
  # DHCPv4 Discover fails immediately ("ipoe: not a IPoE message 2" /
  # "ipoe: failed to create interface", confirmed against accel-ppp's
  # own accel-pppd/ctrl/ipoe/ipoe_netlink.c source: that message means
  # the kernel replied with a generic/unrecognized netlink message
  # instead of a real ipoe-family one, because no such family is
  # registered). KDIR must point at a full kernel module build tree
  # matching the RUNNING kernel, not just headers -- linux-headers-
  # $(uname -r) (installed below) provides exactly that via the
  # standard /lib/modules/$(uname -r)/build symlink.
  # -DBUILD_VLAN_MON_DRIVER=FALSE: a separate optional fast-path module
  # this project's N:1-vlan-free design doesn't need.
  # -DRADIUS=TRUE: this project's whole reason for choosing accel-ppp --
  # real RADIUS auth/accounting against FreeRADIUS (roles/bng's own
  # tasks configure the FreeRADIUS side).
  KDIR="/lib/modules/$(uname -r)/build"
  (
    cd "$BUILD_DIR/build"
    sudo cmake \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DBUILD_IPOE_DRIVER=TRUE \
      -DKDIR="$KDIR" \
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

  # `make install`'s own INSTALL(CODE ...) step (drivers/ipoe/CMakeLists.
  # txt) runs `make -C $KDIR M=<build>/drivers/ipoe modules_install` --
  # confirmed on a real run this path is WRONG: the .ko this same
  # CMakeLists.txt actually builds lands at <build>/drivers/ipoe/driver/
  # ipoe.ko (singular "driver"), not .../drivers/ipoe/drivers/ipoe/...
  # (plural, no such tree exists), so modules_install silently no-ops
  # ("cat: .../modules.order: No such file or directory") and modprobe
  # later fails with "Module ipoe not found". Installing the real .ko
  # manually sidesteps that upstream path mismatch instead of trying to
  # work around it via KDIR/CMake variables.
  KO_PATH="$BUILD_DIR/build/drivers/ipoe/driver/ipoe.ko"
  if [ -f "$KO_PATH" ]; then
    sudo mkdir -p "/lib/modules/$(uname -r)/extra"
    sudo cp "$KO_PATH" "/lib/modules/$(uname -r)/extra/ipoe.ko"
    sudo depmod -a
    ok "ipoe.ko instalado en /lib/modules/$(uname -r)/extra/"
  else
    warn "no se encontró $KO_PATH -- el módulo de kernel puede no haberse compilado, revisa la salida de cmake/make arriba"
  fi
fi

echo "== 3. Módulo de kernel ipoe =="

if lsmod | grep -q '^ipoe '; then
  ok "módulo ipoe ya cargado"
else
  if [ "$CHECK_ONLY" -eq 1 ]; then
    warn "módulo ipoe no cargado -- corre sin --check-only"
  else
    sudo depmod -a
    sudo modprobe ipoe \
      && ok "módulo ipoe cargado" \
      || fail "modprobe ipoe falló -- revisa que linux-headers-$(uname -r) coincida con el kernel corriendo (uname -r)"
    echo "ipoe" | sudo tee /etc/modules-load.d/ipoe.conf >/dev/null
    ok "módulo ipoe persistido en /etc/modules-load.d/ipoe.conf (se carga en cada boot)"
  fi
fi

echo ""
echo "*** accel-ppp listo: $(command -v accel-pppd)"
echo "    accel-cmd (CLI de control): $(command -v accel-cmd || echo 'no encontrado en PATH')"
echo "    Siguiente paso: deploy/vm-lab/ansible/roles/bng despliega /etc/accel-ppp.conf y el unit systemd"
