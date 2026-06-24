#!/usr/bin/env bash
#
# Idempotent installer for Orange-OpenSource/ns-O-RAN-flexric + its real
# FlexRIC + e2sim-kpmv3 (E2AP v1.01 / KPM v3.00 / RC v1.03) dependencies.
#
# Unlike deploy/setup_ns3.sh (stock ns-3 + classic lte module, used by
# simulation/scenario-zero-ddos.cc), this targets the REAL O-RAN E2/KPM
# stack: FlexRIC as the Near-RT RIC, e2sim-kpmv3 as the E2 termination
# library, and mmwave-LENA-oran (ns-3's NR/5G-LENA module, NOT lte) as
# the simulator. These are separate, not interchangeable — see the repo
# layout below.
#
# Steps (each idempotent — checks before doing anything):
#   1. apt build deps (+ g++-13 via the ubuntu-toolchain-r/test PPA —
#      Ubuntu 20.04's own repos only go up to g++-10, but FlexRIC's
#      oie-ric-taap-xapps branch needs a newer C++ standard than that
#      supports)
#   2. Clone + build + install FlexRIC (gitlab.eurecom.fr/mosaic5g/flexric,
#      branch oie-ric-taap-xapps) with -DE2AP_VERSION=E2AP_V1
#      -DKPM_VERSION=KPM_V3_00 — both confirmed valid cache variables/
#      values in that branch's own CMakeLists.txt
#   3. Clone ns-O-RAN-flexric with its two submodules (e2sim-kpmv3,
#      mmwave-LENA-oran)
#   4. Build + install e2sim-kpmv3 via its own build_e2sim.sh (produces
#      and dpkg-installs an e2sim-dev .deb)
#   5. Configure + build mmwave-LENA-oran (./ns3 configure && ./ns3 build)
#
# Usage:
#   ./deploy/setup_ns_oran_flexric.sh                     # installs into ~/flexric, ~/ns-O-RAN-flexric
#   FLEXRIC_DIR=/opt/flexric ORAN_FLEXRIC_DIR=/opt/ns-O-RAN-flexric ./deploy/setup_ns_oran_flexric.sh
#   ./deploy/setup_ns_oran_flexric.sh --check-only         # validate only, never install/build
#   ./deploy/setup_ns_oran_flexric.sh --jobs 4             # parallel build jobs (default: nproc)
#
# After this finishes, see the FlexRIC + e2sim-kpmv3 READMEs for how to
# actually run the Near-RT RIC and an E2 node against each other —
# that wiring is intentionally NOT automated here yet.

set -euo pipefail

FLEXRIC_DIR="${FLEXRIC_DIR:-$HOME/flexric}"
ORAN_FLEXRIC_DIR="${ORAN_FLEXRIC_DIR:-$HOME/ns-O-RAN-flexric}"
FLEXRIC_REPO_URL="https://gitlab.eurecom.fr/mosaic5g/flexric.git"
FLEXRIC_BRANCH="oie-ric-taap-xapps"
ORAN_FLEXRIC_REPO_URL="https://github.com/Orange-OpenSource/ns-O-RAN-flexric"
JOBS="$(nproc 2>/dev/null || echo 2)"
CHECK_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --check-only) CHECK_ONLY=1; shift ;;
    --jobs) JOBS="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

PROBLEMS=0
ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1" >&2; }
fail() { echo "  [FAIL] $1" >&2; PROBLEMS=$((PROBLEMS + 1)); }

# ---------------------------------------------------------------------------
# 1. Build dependencies
# ---------------------------------------------------------------------------

echo "== 1. Dependencias de build (FlexRIC + e2sim-kpmv3) =="

FLEXRIC_APT_PKGS="build-essential git cmake libsctp-dev autoconf automake libtool bison flex libboost-all-dev python3.8"
MISSING_PKGS=""
for pkg in $FLEXRIC_APT_PKGS; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    MISSING_PKGS="$MISSING_PKGS $pkg"
  fi
done

if [ -z "$MISSING_PKGS" ]; then
  ok "todas las dependencias base ya están instaladas"
else
  warn "faltan:${MISSING_PKGS}"
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "instala las dependencias base -- corre sin --check-only"
  else
    echo "  -> instalando:${MISSING_PKGS}"
    sudo apt-get update -qq
    # shellcheck disable=SC2086
    sudo apt-get install -y -qq $MISSING_PKGS
    ok "dependencias base instaladas"
  fi
fi

echo "== 1b. g++-13 (Ubuntu 20.04 solo trae hasta g++-10 de fábrica) =="

if command -v g++-13 >/dev/null 2>&1; then
  ok "g++-13 disponible"
else
  warn "g++-13 no encontrado"
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "instala g++-13 (PPA ubuntu-toolchain-r/test) -- corre sin --check-only"
  else
    echo "  -> agregando ppa:ubuntu-toolchain-r/test e instalando g++-13..."
    sudo apt-get install -y -qq software-properties-common
    sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
    sudo apt-get update -qq
    sudo apt-get install -y -qq g++-13
    if command -v g++-13 >/dev/null 2>&1; then
      ok "g++-13 instalado"
    else
      fail "g++-13 sigue sin estar disponible tras instalar el PPA"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2. FlexRIC (Near-RT RIC)
# ---------------------------------------------------------------------------

echo "== 2. FlexRIC (${FLEXRIC_DIR}, branch ${FLEXRIC_BRANCH}) =="

is_valid_flexric_tree() {
  [ -f "${FLEXRIC_DIR}/CMakeLists.txt" ] && [ -d "${FLEXRIC_DIR}/src" ]
}

if is_valid_flexric_tree; then
  ok "ya existe un árbol FlexRIC en ${FLEXRIC_DIR}"
  CURRENT_BRANCH="$(git -C "$FLEXRIC_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
  if [ "$CURRENT_BRANCH" != "$FLEXRIC_BRANCH" ]; then
    warn "está en '${CURRENT_BRANCH}', no en '${FLEXRIC_BRANCH}'"
  fi
elif [ -d "$FLEXRIC_DIR" ] && [ -n "$(ls -A "$FLEXRIC_DIR" 2>/dev/null)" ]; then
  fail "${FLEXRIC_DIR} existe, no está vacío, y no parece un árbol FlexRIC -- bórralo o elige otro FLEXRIC_DIR"
else
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "${FLEXRIC_DIR} no existe todavía -- corre sin --check-only para clonarlo"
  else
    echo "  -> clonando ${FLEXRIC_REPO_URL} en ${FLEXRIC_DIR}..."
    git clone "$FLEXRIC_REPO_URL" "$FLEXRIC_DIR"
    git -C "$FLEXRIC_DIR" checkout "$FLEXRIC_BRANCH"
    ok "FlexRIC clonado en ${FLEXRIC_DIR}"
  fi
fi

if is_valid_flexric_tree; then
  if dpkg -s e2sim >/dev/null 2>&1 || [ -f "${FLEXRIC_DIR}/build/CMakeCache.txt" ]; then
    ok "FlexRIC ya parece configurado/compilado -- reconstruyendo de forma incremental"
  fi

  if [ "$CHECK_ONLY" -eq 1 ]; then
    if [ ! -f "${FLEXRIC_DIR}/build/CMakeCache.txt" ]; then
      fail "FlexRIC no está compilado todavía -- corre sin --check-only"
    fi
  else
    mkdir -p "${FLEXRIC_DIR}/build"
    (
      cd "${FLEXRIC_DIR}/build"
      CC=gcc-13 CXX=g++-13 cmake .. -DE2AP_VERSION=E2AP_V1 -DKPM_VERSION=KPM_V3_00
      make -j "$JOBS"
      sudo make install
    )
    ok "FlexRIC compilado e instalado"
  fi
else
  fail "se omite el build de FlexRIC -- el árbol no es válido (ver paso 2)"
fi

# ---------------------------------------------------------------------------
# 3. ns-O-RAN-flexric (+ submódulos e2sim-kpmv3, mmwave-LENA-oran)
# ---------------------------------------------------------------------------

echo "== 3. ns-O-RAN-flexric (${ORAN_FLEXRIC_DIR}) =="

is_valid_oran_flexric_tree() {
  [ -f "${ORAN_FLEXRIC_DIR}/.gitmodules" ] \
    && [ -f "${ORAN_FLEXRIC_DIR}/e2sim-kpmv3/e2sim/CMakeLists.txt" ] \
    && [ -f "${ORAN_FLEXRIC_DIR}/mmwave-LENA-oran/ns3" ]
}

if is_valid_oran_flexric_tree; then
  ok "ya existe un árbol ns-O-RAN-flexric válido (con submódulos) en ${ORAN_FLEXRIC_DIR}"
elif [ -d "$ORAN_FLEXRIC_DIR" ] && [ -n "$(ls -A "$ORAN_FLEXRIC_DIR" 2>/dev/null)" ]; then
  warn "${ORAN_FLEXRIC_DIR} existe pero los submódulos no están completos -- intentando 'git submodule update --init'"
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "submódulos incompletos -- corre sin --check-only"
  else
    git -C "$ORAN_FLEXRIC_DIR" submodule update --init --recursive
    if is_valid_oran_flexric_tree; then
      ok "submódulos completados"
    else
      fail "${ORAN_FLEXRIC_DIR} sigue sin parecer un árbol válido tras actualizar submódulos"
    fi
  fi
else
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "${ORAN_FLEXRIC_DIR} no existe todavía -- corre sin --check-only para clonarlo"
  else
    echo "  -> clonando ${ORAN_FLEXRIC_REPO_URL} (con submódulos) en ${ORAN_FLEXRIC_DIR}..."
    git clone --recurse-submodules "$ORAN_FLEXRIC_REPO_URL" "$ORAN_FLEXRIC_DIR"
    ok "ns-O-RAN-flexric clonado en ${ORAN_FLEXRIC_DIR}"
  fi
fi

# ---------------------------------------------------------------------------
# 4. e2sim-kpmv3 (E2 termination library)
# ---------------------------------------------------------------------------

echo "== 4. e2sim-kpmv3 =="

E2SIM_DIR="${ORAN_FLEXRIC_DIR}/e2sim-kpmv3/e2sim"

if [ ! -f "${E2SIM_DIR}/build_e2sim.sh" ]; then
  fail "se omite el build de e2sim-kpmv3 -- ${E2SIM_DIR}/build_e2sim.sh no existe (ver paso 3)"
elif dpkg -s e2sim-dev >/dev/null 2>&1; then
  ok "e2sim-dev ya está instalado"
  if [ "$CHECK_ONLY" -eq 0 ]; then
    echo "  -> re-corriendo build_e2sim.sh por si hay cambios..."
    ( cd "$E2SIM_DIR" && mkdir -p build && sudo ./build_e2sim.sh 2 )
  fi
else
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "e2sim-dev no está instalado -- corre sin --check-only"
  else
    echo "  -> compilando e instalando e2sim-kpmv3 (build_e2sim.sh)..."
    ( cd "$E2SIM_DIR" && mkdir -p build && sudo ./build_e2sim.sh 2 )
    if dpkg -s e2sim-dev >/dev/null 2>&1; then
      ok "e2sim-dev instalado"
    else
      fail "build_e2sim.sh corrió pero e2sim-dev no quedó instalado"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 5. mmwave-LENA-oran (ns-3 NR/5G-LENA fork)
# ---------------------------------------------------------------------------

echo "== 5. mmwave-LENA-oran (módulo NR, NO el lte clásico) =="

MMWAVE_DIR="${ORAN_FLEXRIC_DIR}/mmwave-LENA-oran"

if [ ! -x "${MMWAVE_DIR}/ns3" ]; then
  fail "se omite la configuración/build -- ${MMWAVE_DIR}/ns3 no existe o no es ejecutable (ver paso 3)"
else
  if [ "$CHECK_ONLY" -eq 1 ]; then
    if [ ! -d "${MMWAVE_DIR}/build" ] && [ ! -d "${MMWAVE_DIR}/cmake-cache" ]; then
      fail "mmwave-LENA-oran no está configurado/compilado todavía -- corre sin --check-only"
    fi
  else
    ( cd "$MMWAVE_DIR" && ./ns3 configure && ./ns3 build -j "$JOBS" )
    ok "mmwave-LENA-oran configurado y compilado"
  fi
fi

echo ""
if [ "$PROBLEMS" -eq 0 ]; then
  echo "*** FlexRIC + e2sim-kpmv3 + mmwave-LENA-oran listos."
  echo "    FlexRIC:          ${FLEXRIC_DIR}"
  echo "    ns-O-RAN-flexric: ${ORAN_FLEXRIC_DIR}"
  echo "    Próximo paso (manual, no automatizado por este script): levantar"
  echo "    el Near-RT RIC de FlexRIC y correr un escenario de"
  echo "    ${MMWAVE_DIR}/scratch contra él -- ver los README de cada repo."
  exit 0
else
  echo "*** $PROBLEMS problema(s) sin resolver -- revisa los [FAIL] arriba." >&2
  exit 1
fi
