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

FLEXRIC_APT_PKGS="build-essential git cmake python3-pip libsctp-dev autoconf automake libtool bison flex libboost-all-dev python3.8"
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

echo "== 1c. cmake reciente (oie-ric-taap-xapps necesita >=3.19, apt en 20.04 trae 3.16) =="

# examples/xApp/c/monitor/RRC_MESSAGES/CMakeLists.txt does
# add_library(asn1_nr_rrc_hdrs INTERFACE \${nr_rrc_headers}) -- passing
# header sources to an INTERFACE library, which CMake only allows since
# 3.19. The branch's own cmake_minimum_required(VERSION 3.16) is wrong/
# stale for this — not a mistake on our side. Installed via pip3 --user
# instead of touching the system cmake package, since e2sim-kpmv3 and
# mmwave-LENA-oran's own builds are fine with whatever's already there.
CMAKE_BIN="cmake"
CMAKE_MIN_VERSION="3.19"

version_ge() { [ "$(printf '%s\n%s' "$1" "$2" | sort -V | head -n1)" = "$2" ]; }

if command -v cmake >/dev/null 2>&1; then
  SYSTEM_CMAKE_VERSION="$(cmake --version | head -1 | awk '{print $3}')"
else
  SYSTEM_CMAKE_VERSION=""
fi

if [ -n "$SYSTEM_CMAKE_VERSION" ] && version_ge "$SYSTEM_CMAKE_VERSION" "$CMAKE_MIN_VERSION"; then
  ok "cmake del sistema (${SYSTEM_CMAKE_VERSION}) ya alcanza"
else
  warn "cmake del sistema (${SYSTEM_CMAKE_VERSION:-no encontrado}) es menor a ${CMAKE_MIN_VERSION}"
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "instala un cmake >= ${CMAKE_MIN_VERSION} -- corre sin --check-only (se instala vía pip3 --user, sin tocar el del sistema)"
  else
    echo "  -> instalando cmake reciente vía pip3 --user..."
    pip3 install --user --upgrade "cmake>=3.22" --quiet
    CMAKE_BIN="$HOME/.local/bin/cmake"
    if [ -x "$CMAKE_BIN" ]; then
      ok "cmake $("$CMAKE_BIN" --version | head -1 | awk '{print $3}') instalado en ${CMAKE_BIN}"
    else
      fail "no se pudo instalar un cmake reciente vía pip3 --user"
    fi
  fi
fi

echo "== 1d. asn1c (fork mouse07410 @ 940dd5f, instalado en /opt/asn1c) =="

# examples/xApp/c/monitor/RRC_MESSAGES/CMakeLists.txt hace
# find_program(ASN1C_EXEC_PATH asn1c HINTS /opt/asn1c/bin) -- el apt
# "asn1c" (donde existe) es una versión distinta/incompatible. El fork +
# commit + prefix exactos vienen de FlexRIC's propio
# docker/Dockerfile.flexric.ubuntu, no son una elección nuestra.
ASN1C_PREFIX="/opt/asn1c"
ASN1C_REPO_URL="https://github.com/mouse07410/asn1c"
ASN1C_COMMIT="940dd5fa9f3917913fd487b13dfddfacd0ded06e"
ASN1C_BUILD_DIR="/tmp/asn1c-build"

if [ -x "${ASN1C_PREFIX}/bin/asn1c" ]; then
  ok "asn1c ya está instalado en ${ASN1C_PREFIX}/bin/asn1c"
else
  if [ "$CHECK_ONLY" -eq 1 ]; then
    fail "asn1c no está instalado en ${ASN1C_PREFIX} -- corre sin --check-only"
  else
    echo "  -> clonando ${ASN1C_REPO_URL} @ ${ASN1C_COMMIT}..."
    rm -rf "$ASN1C_BUILD_DIR"
    git clone "$ASN1C_REPO_URL" "$ASN1C_BUILD_DIR"
    git -C "$ASN1C_BUILD_DIR" checkout "$ASN1C_COMMIT"
    (
      cd "$ASN1C_BUILD_DIR"
      autoreconf -iv
      ./configure --prefix "$ASN1C_PREFIX"
      make -j "$JOBS"
      sudo make install
    )
    if [ -x "${ASN1C_PREFIX}/bin/asn1c" ]; then
      ok "asn1c instalado en ${ASN1C_PREFIX}/bin/asn1c"
    else
      fail "el build de asn1c corrió pero ${ASN1C_PREFIX}/bin/asn1c no existe"
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

  # Root cause of "Measurement Name not yet supported" x23 per UE
  # against real ns-3 data: confirmed in mmwave-LENA-oran's
  # contrib/oran-interface/helper/mmwave-indication-message-helper.cc
  # (MmWaveIndicationMessageHelper::AddDuUePmItem) that ns-3 genuinely
  # sends 23 named measurements per UE per indication (22 long + 1
  # double -- exactly matching the observed count), but every name has
  # a ".UEID" suffix (e.g. "DRB.UEThpDl.UEID", "RRU.PrbUsedDl.UEID")
  # that this xApp's log_int_value/log_real_value compare against
  # exact, suffix-less names ("DRB.UEThpDl", "RRU.PrbUsedDl") --  so
  # real data IS present in every indication, this printer just never
  # recognized the name. Patches in the two real per-UE values useful
  # for this proposal's detection pipeline: per-UE DL throughput and
  # per-UE DL PRB usage.
  XAPP_KPM_MONI_C="${FLEXRIC_DIR}/examples/xApp/c/monitor/xapp_kpm_moni.c"
  if [ -f "$XAPP_KPM_MONI_C" ] && ! grep -q "PATCHED (oran-multidomain-ddos-ueid)" "$XAPP_KPM_MONI_C"; then
    if [ "$CHECK_ONLY" -eq 0 ]; then
      echo "  -> agregando soporte para nombres de medicion con sufijo .UEID en xapp_kpm_moni..."
      sed -i 's#} else if (cmp_str_ba("DRB.PdcpSduVolumeUL", name) == 0) {#} else if (cmp_str_ba("RRU.PrbUsedDl.UEID", name) == 0) { // PATCHED (oran-multidomain-ddos-ueid): real ns-3 per-UE DL PRB usage, sent with a .UEID suffix this xApp did not originally recognize\n    printf("RRU.PrbUsedDl.UEID = %d [PRBs]\\n", meas_record.int_val);\n  } else if (cmp_str_ba("DRB.PdcpSduVolumeUL", name) == 0) {#' "$XAPP_KPM_MONI_C"
      sed -i 's#} else if (cmp_str_ba("DRB.UEThpUl", name) == 0) {#} else if (cmp_str_ba("DRB.UEThpDl.UEID", name) == 0) { // PATCHED (oran-multidomain-ddos-ueid): real ns-3 per-UE DL throughput, sent with a .UEID suffix this xApp did not originally recognize\n    printf("DRB.UEThpDl.UEID = %.2f [kbps]\\n", meas_record.real_val);\n  } else if (cmp_str_ba("DRB.UEThpUl", name) == 0) {#' "$XAPP_KPM_MONI_C"
      if grep -q "PATCHED (oran-multidomain-ddos-ueid)" "$XAPP_KPM_MONI_C"; then
        ok "xapp_kpm_moni parcheado para reconocer RRU.PrbUsedDl.UEID / DRB.UEThpDl.UEID"
      else
        fail "el patch de xapp_kpm_moni no se aplico -- revisa los textos ancla contra el archivo real"
      fi
    fi
  elif [ -f "$XAPP_KPM_MONI_C" ]; then
    ok "xapp_kpm_moni ya esta parcheado para .UEID"
  fi

  # Patched both the .UEID-suffix mismatch above and a real heap buffer
  # overflow in ns-3's MeasurementItem name encoding (see the
  # asn1c-types.cc/kpm-indication.cc patch step below), yet every
  # measurement name STILL fails to match anything -- there is at least
  # one more bug in this chain we have not found yet. Dumps the real
  # length + raw hex bytes of every measurement name FlexRIC actually
  # decodes, right before the name comparison, so the next debugging
  # step is reading real bytes instead of guessing another string to
  # try.
  if [ -f "$XAPP_KPM_MONI_C" ] && ! grep -q "PATCHED-DIAG3" "$XAPP_KPM_MONI_C"; then
    if [ "$CHECK_ONLY" -eq 0 ]; then
      echo "  -> agregando dump de bytes crudos del nombre de medicion en xapp_kpm_moni..."
      python3 - "$XAPP_KPM_MONI_C" <<'PYEOF'
import sys

path = sys.argv[1]
with open(path) as f:
    text = f.read()

anchor = "  get_meas_value[meas_record.value](meas_type.name, meas_record);\n"
dump = (
    "  printf(\"[PATCHED-DIAG3] name.len=%zu bytes=\", meas_type.name.len);\n"
    "  for (size_t i = 0; i < meas_type.name.len; i++) {\n"
    "    printf(\"%02x \", meas_type.name.buf[i]);\n"
    "  }\n"
    "  printf(\" ascii=\");\n"
    "  for (size_t i = 0; i < meas_type.name.len; i++) {\n"
    "    unsigned char c = meas_type.name.buf[i];\n"
    "    printf(\"%c\", (c >= 32 && c < 127) ? c : '.');\n"
    "  }\n"
    "  printf(\"\\n\");\n"
    + anchor
)
assert text.count(anchor) == 1, f"expected exactly one anchor match, found {text.count(anchor)}"
text = text.replace(anchor, dump, 1)

with open(path, "w") as f:
    f.write(text)
PYEOF
      if [ $? -eq 0 ] && grep -q "PATCHED-DIAG3" "$XAPP_KPM_MONI_C"; then
        ok "dump de bytes crudos agregado a xapp_kpm_moni"
      else
        fail "el dump de diagnostico no se agrego -- revisa el texto ancla contra el archivo real"
      fi
    fi
  fi

  if [ "$CHECK_ONLY" -eq 1 ]; then
    if [ ! -f "${FLEXRIC_DIR}/build/CMakeCache.txt" ]; then
      fail "FlexRIC no está compilado todavía -- corre sin --check-only"
    fi
  else
    # A build/ left over from before asn1c was installed has
    # ASN1C_EXEC_PATH cached as NOTFOUND -- CMake won't re-run
    # find_program for an already-cached variable, so that stale value
    # would otherwise survive a plain re-configure. Surgically deleting
    # just that cache line is fragile (CMakeCache.txt from a configure
    # that itself errored out partway can already be malformed, and
    # sed-ing it further only compounds that) -- wiping build/ and
    # reconfiguring clean is slower but actually reliable.
    if [ -f "${FLEXRIC_DIR}/build/CMakeCache.txt" ] \
       && grep -q "ASN1C_EXEC_PATH.*NOTFOUND" "${FLEXRIC_DIR}/build/CMakeCache.txt" 2>/dev/null; then
      echo "  -> build/ tiene ASN1C_EXEC_PATH cacheado como NOTFOUND (de antes de instalar asn1c) -- reconfigurando limpio..."
      rm -rf "${FLEXRIC_DIR}/build"
    fi
    mkdir -p "${FLEXRIC_DIR}/build"
    (
      cd "${FLEXRIC_DIR}/build"
      CC=gcc-13 CXX=g++-13 "$CMAKE_BIN" .. -DE2AP_VERSION=E2AP_V1 -DKPM_VERSION=KPM_V3_00
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
# 4b. Patch: MmWaveEnbNetDevice::CheckReportingFlag siempre reporta
# ---------------------------------------------------------------------------

echo "== 4b. Patch: bypass del umbral de PRB en CheckReportingFlag =="

MMWAVE_DIR="${ORAN_FLEXRIC_DIR}/mmwave-LENA-oran"
MMWAVE_ENB_DEVICE_CC="${MMWAVE_DIR}/src/mmwave/model/mmwave-enb-net-device.cc"

# Confirmed empirically: ns-3's KpmFunctionDescription only advertises
# RIC Report Style 4 (condition-based) -- there is no Style 5
# (periodic) to subscribe to instead. Style 4's CheckReportingFlag()
# only calls BuildAndSendReportMessage() once a PRB-average threshold
# (chosen by whichever xApp subscribes, e.g. xapp_kpm_moni's default)
# is crossed -- with our scenario's modest test traffic, that threshold
# never crossed, so FlexRIC never received a single E2 INDICATION even
# though the E2 SETUP/RIC SUBSCRIPTION handshake succeeded for real.
# This proposal needs continuous monitoring, not a condition-triggered
# alert, so the threshold check is bypassed here -- a deliberate local
# patch to our own checkout, not upstream's intended behavior.
if [ -f "$MMWAVE_ENB_DEVICE_CC" ]; then
  if grep -q "PATCHED (oran-multidomain-ddos)" "$MMWAVE_ENB_DEVICE_CC"; then
    ok "CheckReportingFlag ya está parcheado"
  else
    if [ "$CHECK_ONLY" -eq 1 ]; then
      fail "CheckReportingFlag sin parchear -- corre sin --check-only"
    else
      echo "  -> parcheando CheckReportingFlag para reportar sin esperar el umbral de PRB..."
      sed -i 's#if (shouldReport)#if (1) // PATCHED (oran-multidomain-ddos): always report once subscribed; bypasses the PRB threshold since this proposal needs continuous monitoring, not condition-triggered alerts#' "$MMWAVE_ENB_DEVICE_CC"
      if grep -q "PATCHED (oran-multidomain-ddos)" "$MMWAVE_ENB_DEVICE_CC"; then
        ok "CheckReportingFlag parcheado"
      else
        fail "el patch no se aplicó -- revisa si mmwave-enb-net-device.cc cambió de forma upstream"
      fi
    fi
  fi
else
  fail "no se encontró ${MMWAVE_ENB_DEVICE_CC} -- ¿está clonado ns-O-RAN-flexric? (ver paso 3)"
fi

# The shouldReport bypass above made zero observable difference on a
# real run -- same immediate subscribe-then-unsubscribe, zero
# indications sent. That whole block (bypass included) sits inside
# `if (!sub_map.empty())`, itself inside `if (!m_stopSendingMessages &&
# m_hasValidSubscription)`. KpmSubscriptionCallback reads the same
# sub_map successfully moments earlier (the printed Action Definition
# Format/Test Condition fields come from it) -- so either sub_map goes
# empty by the time this LATER, separately-scheduled call runs, or
# m_hasValidSubscription/m_stopSendingMessages aren't what we assume.
# Diagnostic print to find out which, independent of the bypass patch
# above (separate idempotency marker).
if [ -f "$MMWAVE_ENB_DEVICE_CC" ] && ! grep -q "PATCHED-DIAG" "$MMWAVE_ENB_DEVICE_CC"; then
  if [ "$CHECK_ONLY" -eq 0 ]; then
    echo "  -> agregando print de diagnóstico en CheckReportingFlag..."
    # Tolerates either "SubscriptionMapRef();" or "SubscriptionMapRef ();"
    # -- not certain which spacing the real file uses. Matches inside
    # both KpmSubscriptionCallback and CheckReportingFlag (same line
    # appears in both); printing from both is harmless extra signal,
    # not a bug, since we want to compare sub_map.size() across both.
    sed -i '/const auto &sub_map = m_e2term->SubscriptionMapRef *();/a\      std::cout << "[PATCHED-DIAG] sub_map.size()=" << sub_map.size() << " m_hasValidSubscription=" << m_hasValidSubscription << " m_stopSendingMessages=" << m_stopSendingMessages << std::endl;' "$MMWAVE_ENB_DEVICE_CC"
    if grep -q "PATCHED-DIAG" "$MMWAVE_ENB_DEVICE_CC"; then
      ok "print de diagnóstico agregado"
    else
      fail "el print de diagnóstico no se insertó -- el texto ancla ('const auto &sub_map = m_e2term->SubscriptionMapRef ();') puede no coincidir exactamente (revisa espacios/paréntesis en el archivo real)"
    fi
  fi
fi

# Confirmed from the real file (pasted by the user): no exception ever
# gets thrown/caught inside CheckReportingFlag's try block (zero
# "Error checking PRB usage" lines across a full run with ~45
# sub_map.size()=10 ticks), and BuildAndSendReportMessage is only ever
# called ONCE per subscription anyway -- the very first time
# currentPrbAvg becomes >= 0 (the "else" branch's call is commented
# out, despite its comment saying "keep sending reports"; that's
# upstream's existing code, not something we touched). With
# MAX_PRB_HISTORY=10 and ~45 ticks observed in a 20-25s run,
# currentPrbAvg should go >= 0 well before the run ends -- yet zero
# indications ever reached the xApp. These two prints narrow down
# whether currentPrbAvg ever actually goes non-negative, and whether
# BuildAndSendReportMessage is reached at all.
if [ -f "$MMWAVE_ENB_DEVICE_CC" ] && ! grep -q "PATCHED-DIAG2" "$MMWAVE_ENB_DEVICE_CC"; then
  if [ "$CHECK_ONLY" -eq 0 ]; then
    echo "  -> agregando prints de diagnóstico para currentPrbAvg / BuildAndSendReportMessage..."
    sed -i '/double currentPrbAvg = CalculatePrbAverage();/a\          std::cout << "[PATCHED-DIAG2] currentPrbAvg=" << currentPrbAvg << std::endl;' "$MMWAVE_ENB_DEVICE_CC"
    sed -i '/^[[:space:]]*BuildAndSendReportMessage(m_lastSubscriptionParams);[[:space:]]*$/i\              std::cout << "[PATCHED-DIAG2] calling BuildAndSendReportMessage" << std::endl;' "$MMWAVE_ENB_DEVICE_CC"
    if grep -q "PATCHED-DIAG2" "$MMWAVE_ENB_DEVICE_CC"; then
      ok "prints de diagnóstico (currentPrbAvg / BuildAndSendReportMessage) agregados"
    else
      fail "los prints de diagnóstico no se insertaron -- revisa los textos ancla contra el archivo real"
    fi
  fi
fi

# Root cause, confirmed via NS_LOG="MmWaveEnbNetDevice=error": every
# single CheckReportingFlag tick throws "bad any_cast" (silently
# swallowed by the surrounding catch, since NS_LOG_ERROR output needs
# NS_LOG explicitly enabled to print at all -- that's why nothing
# showed up earlier just grepping the log for ERROR with no env var
# set). Confirmed in contrib/oran-interface/model/oran-interface.cc
# (StoreSubscriptionDetail's call sites around line 269-293): "Test
# Condition Value" can be stored as int, bool, double (valueReal), or
# a string buffer depending on which ASN.1 IE choice the real
# subscription used -- CheckReportingFlag's plain
# std::any_cast<int>(value) only ever worked for one of those. This
# adds a small helper using any_cast's pointer overload (returns
# nullptr instead of throwing) to try int/double/bool in order, and
# points CheckReportingFlag's "Test Condition Value" extraction at it.
if [ -f "$MMWAVE_ENB_DEVICE_CC" ] && ! grep -q "AnyCastToInt_oran_ddos_patch" "$MMWAVE_ENB_DEVICE_CC"; then
  if [ "$CHECK_ONLY" -eq 0 ]; then
    echo "  -> agregando AnyCastToInt_oran_ddos_patch (bad_any_cast en Test Condition Value)..."
    # Plain Python string ops instead of sed's a\ multi-line + & escaping
    # -- that combination is fragile/ambiguous enough across sed
    # versions that it's not worth risking on a patch this important.
    python3 - "$MMWAVE_ENB_DEVICE_CC" <<'PYEOF'
import sys

path = sys.argv[1]
with open(path) as f:
    text = f.read()

anchor = 'NS_LOG_COMPONENT_DEFINE ("MmWaveEnbNetDevice");\n'
helper = (
    anchor
    + "\n"
    + "static int AnyCastToInt_oran_ddos_patch(const std::any& a, int def = 0)\n"
    + "{\n"
    + "  if (auto p = std::any_cast<int>(&a)) { return *p; }\n"
    + "  if (auto p = std::any_cast<double>(&a)) { return static_cast<int>(*p); }\n"
    + "  if (auto p = std::any_cast<bool>(&a)) { return *p ? 1 : 0; }\n"
    + "  return def;\n"
    + "}\n"
)
assert text.count(anchor) == 1, f"expected exactly one anchor match, found {text.count(anchor)}"
text = text.replace(anchor, helper, 1)

old_line = "        int threshold = std::any_cast<int>(value);\n"
new_line = (
    "        int threshold = AnyCastToInt_oran_ddos_patch(value);"
    " // PATCHED (oran-multidomain-ddos-anycast): the real type behind value"
    " varies (int, double, bool, or string) depending on which IE choice was"
    " used when building the subscription; a plain any_cast<int> threw"
    " bad_any_cast on every tick\n"
)
assert text.count(old_line) == 1, f"expected exactly one threshold-line match, found {text.count(old_line)}"
text = text.replace(old_line, new_line, 1)

with open(path, "w") as f:
    f.write(text)
PYEOF
    if [ $? -eq 0 ] && grep -q "AnyCastToInt_oran_ddos_patch(value)" "$MMWAVE_ENB_DEVICE_CC"; then
      ok "AnyCastToInt_oran_ddos_patch agregado y aplicado al threshold"
    else
      fail "el patch de any_cast no se aplicó completo -- revisa los textos ancla (NS_LOG_COMPONENT_DEFINE / la línea exacta de threshold) contra el archivo real"
    fi
  fi
fi

# Root cause of ALL 23 per-UE measurements still printing "Measurement
# Name not yet supported" even after patching xapp_kpm_moni for the
# .UEID suffix (confirmed: 0 matches, not just the unpatched 2):
# MeasurementItem's constructor (contrib/oran-interface/model/
# asn1c-types.cc, ~line 812) allocates the measurement name's OCTET
# STRING buffer as `calloc(1, sizeof(OCTET_STRING))` -- the size of the
# OCTET_STRING *struct* itself (a pointer + a size_t, ~16 bytes), NOT
# `name.length()` bytes -- then memcpy's the full name (up to 28 bytes
# for "CARR.PDSCHMCSDist.Bin1.UEID") into that too-small buffer. Every
# measurement name longer than ~16 bytes overflows into adjacent heap
# memory, corrupting whatever name FlexRIC actually receives -- which
# is why no exact-string comparison on the receiving end could ever
# match, regardless of which names that comparison knows about. The
# exact same bug pattern exists a second time in kpm-indication.cc's
# (unused on this path, but worth fixing for consistency) dead
# "DRB.RlcSduDelayDl_Fake" code path.
declare -a NAME_BUFFER_OVERFLOW_FILES=(
  "${MMWAVE_DIR}/contrib/oran-interface/model/asn1c-types.cc"
  "${MMWAVE_DIR}/contrib/oran-interface/model/kpm-indication.cc"
)
for f in "${NAME_BUFFER_OVERFLOW_FILES[@]}"; do
  if [ -f "$f" ] && ! grep -q "PATCHED (oran-multidomain-ddos-namebuf)" "$f"; then
    if [ "$CHECK_ONLY" -eq 0 ]; then
      echo "  -> corrigiendo el tamano del buffer del nombre de medicion en $(basename "$f")..."
      sed -i 's#m_measName->buf = (uint8_t \*) calloc (1, sizeof (OCTET_STRING));#m_measName->buf = (uint8_t *) calloc (name.length (), sizeof (uint8_t)); // PATCHED (oran-multidomain-ddos-namebuf): was calloc(1, sizeof(OCTET_STRING)), the size of that struct rather than the name length -- overflowing for any measurement name longer than about 16 bytes#' "$f"
      if grep -q "PATCHED (oran-multidomain-ddos-namebuf)" "$f"; then
        ok "buffer del nombre de medicion corregido en $(basename "$f")"
      else
        fail "el patch del buffer de nombre no se aplico en $(basename "$f") -- revisa el texto ancla contra el archivo real"
      fi
    fi
  elif [ -f "$f" ]; then
    ok "$(basename "$f") ya tiene el buffer del nombre de medicion corregido"
  fi
done

# ---------------------------------------------------------------------------
# 5. mmwave-LENA-oran (ns-3 NR/5G-LENA fork)
# ---------------------------------------------------------------------------

echo "== 5. mmwave-LENA-oran (módulo NR, NO el lte clásico) =="

if [ ! -x "${MMWAVE_DIR}/ns3" ]; then
  fail "se omite la configuración/build -- ${MMWAVE_DIR}/ns3 no existe o no es ejecutable (ver paso 3)"
else
  if [ "$CHECK_ONLY" -eq 1 ]; then
    if [ ! -d "${MMWAVE_DIR}/build" ] && [ ! -d "${MMWAVE_DIR}/cmake-cache" ]; then
      fail "mmwave-LENA-oran no está configurado/compilado todavía -- corre sin --check-only"
    fi
  else
    # scratch/orange-rf-channel-reconfiguration.cc (one of the repo's
    # own bundled examples, not anything we need) is missing two
    # standard includes -- ./ns3 build builds every scratch example
    # unconditionally, so this one upstream bug otherwise fails the
    # whole build even though every actual library (oran-interface,
    # mmwave, nr, sionna, ...) compiles fine on its own.
    BROKEN_SCRATCH="${MMWAVE_DIR}/scratch/orange-rf-channel-reconfiguration.cc"
    if [ -f "$BROKEN_SCRATCH" ] && ! grep -q "#include <iomanip>" "$BROKEN_SCRATCH"; then
      echo "  -> parcheando includes faltantes en $(basename "$BROKEN_SCRATCH")..."
      sed -i '1i #include <iomanip>\n#include <sys/time.h>' "$BROKEN_SCRATCH"
    fi

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
