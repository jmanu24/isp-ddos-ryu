#!/usr/bin/env bash
#
# run_oran_e2_test.sh — O-RAN multidomain DDoS proposal.
#
# Orchestrates the full real-E2/FlexRIC smoke test in one command
# instead of 4 manually-timed terminals. Starts, in order: nearRT-RIC
# (background) -> builds + runs the ns-3 test scenario (foreground,
# real-time-paced via RealtimeSimulatorImpl) -> xapp_kpm_moni a few
# seconds in (background, output captured to a file) -> the
# log-to-CSV parser (background, tailing that file). Tears everything
# down when the ns-3 scenario exits, then prints a diagnostic summary
# instead of requiring you to scroll 4 separate terminal histories.
#
# Usage:
#   FLEXRIC_DIR=~/flexric NS3_DIR=~/ns-O-RAN-flexric/mmwave-LENA-oran \
#     ./simulation/run_oran_e2_test.sh --sim-time 25 --n-ue 2
#
# Env vars (both default to the paths used throughout this session):
#   FLEXRIC_DIR   path to the FlexRIC checkout (needs build/examples/...)
#   NS3_DIR       path to the mmwave-LENA-oran checkout (needs ./ns3)
#   PYTHON        interpreter for the CSV parser (default: this repo's
#                 venv/bin/python3, falling back to plain python3)

set -uo pipefail  # not -e: keep going on partial failures so the summary still prints

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLEXRIC_DIR="${FLEXRIC_DIR:-$HOME/flexric}"
NS3_DIR="${NS3_DIR:-$HOME/ns-O-RAN-flexric/mmwave-LENA-oran}"
SCENARIO_SRC="${REPO_DIR}/simulation/test_oran_e2_logging.cc"
SCRATCH_SUBDIR="oran-test"

SIM_TIME=25
N_UE=2
XAPP_DELAY_S=3
XAPP_DURATION=20
OUT_DIR="/tmp/oran_e2_test_$(date +%s)"

while [ $# -gt 0 ]; do
  case "$1" in
    --sim-time) SIM_TIME="$2"; shift 2 ;;
    --n-ue) N_UE="$2"; shift 2 ;;
    --xapp-delay) XAPP_DELAY_S="$2"; shift 2 ;;
    --xapp-duration) XAPP_DURATION="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage: run_oran_e2_test.sh [options]
  --sim-time N        ns-3 scenario duration in (real, paced) seconds [25]
  --n-ue N            number of UEs in the scenario [2]
  --xapp-delay N      seconds after ns-3 starts before launching xapp_kpm_moni [3]
  --xapp-duration N   XAPP_DURATION passed to xapp_kpm_moni [20]
  --out-dir DIR       where to write logs + the parsed CSV [/tmp/oran_e2_test_<ts>]
EOF
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

mkdir -p "$OUT_DIR"
echo "[run_oran_e2_test] logs in ${OUT_DIR}"

RIC_PID=""
XAPP_PID=""
PARSER_PID=""

cleanup() {
  echo "[run_oran_e2_test] cleaning up..."
  [ -n "$XAPP_PID" ] && kill "$XAPP_PID" 2>/dev/null
  [ -n "$PARSER_PID" ] && kill "$PARSER_PID" 2>/dev/null
  [ -n "$RIC_PID" ] && kill "$RIC_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# 0. Sanity checks
# ---------------------------------------------------------------------------

if [ ! -x "${FLEXRIC_DIR}/build/examples/ric/nearRT-RIC" ]; then
  echo "no se encontró ${FLEXRIC_DIR}/build/examples/ric/nearRT-RIC -- ¿FLEXRIC_DIR correcto?" >&2
  exit 1
fi
if [ ! -x "${NS3_DIR}/ns3" ]; then
  echo "no se encontró ${NS3_DIR}/ns3 -- ¿NS3_DIR correcto?" >&2
  exit 1
fi

# A nearRT-RIC left over from a previous crashed run (this session hit
# this repeatedly) would make the new one fail to bind port 36421.
pkill -f "build/examples/ric/nearRT-RIC" 2>/dev/null
sleep 1

# ---------------------------------------------------------------------------
# 1. Copy scenario + build
# ---------------------------------------------------------------------------

mkdir -p "${NS3_DIR}/scratch/${SCRATCH_SUBDIR}"
cp "$SCENARIO_SRC" "${NS3_DIR}/scratch/${SCRATCH_SUBDIR}/"
echo "[run_oran_e2_test] building..."
if ! ( cd "$NS3_DIR" && ./ns3 build test_oran_e2_logging > "${OUT_DIR}/build.log" 2>&1 ); then
  echo "[run_oran_e2_test] BUILD FAILED -- see ${OUT_DIR}/build.log" >&2
  tail -40 "${OUT_DIR}/build.log"
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. nearRT-RIC (background)
# ---------------------------------------------------------------------------

echo "[run_oran_e2_test] starting nearRT-RIC..."
( cd "$FLEXRIC_DIR" && ./build/examples/ric/nearRT-RIC > "${OUT_DIR}/nearRT-RIC.log" 2>&1 ) &
RIC_PID=$!
sleep 2

if ! kill -0 "$RIC_PID" 2>/dev/null; then
  echo "[run_oran_e2_test] nearRT-RIC died immediately -- see ${OUT_DIR}/nearRT-RIC.log" >&2
  cat "${OUT_DIR}/nearRT-RIC.log"
  exit 1
fi

# ---------------------------------------------------------------------------
# 3. xApp + CSV parser, both starting XAPP_DELAY_S into the run
# (background) -- fixed, scripted timing instead of a human switching
# terminals, since RealtimeSimulatorImpl already gives a real,
# predictable wall-clock window to land in.
# ---------------------------------------------------------------------------

(
  sleep "$XAPP_DELAY_S"
  cd "$FLEXRIC_DIR"
  XAPP_DURATION="$XAPP_DURATION" ./build/examples/xApp/c/monitor/xapp_kpm_moni > "${OUT_DIR}/xapp_kpm_moni.log" 2>&1
) &
XAPP_PID=$!

PYTHON="${PYTHON:-${REPO_DIR}/venv/bin/python3}"
[ -x "$PYTHON" ] || PYTHON="python3"
(
  sleep "$XAPP_DELAY_S"
  "$PYTHON" "${REPO_DIR}/simulation/parse_xapp_kpm_log.py" \
    --log-path "${OUT_DIR}/xapp_kpm_moni.log" \
    --out-csv "${OUT_DIR}/ddos_xapp_events.csv" \
    > "${OUT_DIR}/parser.log" 2>&1
) &
PARSER_PID=$!

# ---------------------------------------------------------------------------
# 4. ns-3 scenario (foreground) -- this is what actually paces the
# whole test in real time
# ---------------------------------------------------------------------------

echo "[run_oran_e2_test] running ns-3 scenario for ${SIM_TIME}s (real time, please wait)..."
(
  cd "$NS3_DIR"
  ./ns3 run "scratch/${SCRATCH_SUBDIR}/test_oran_e2_logging --simTime=${SIM_TIME} --nUe=${N_UE}"
) > "${OUT_DIR}/ns3.log" 2>&1

echo "[run_oran_e2_test] ns-3 scenario finished"

# Let the xApp/parser flush their tail end before tearing down.
sleep 2
kill "$XAPP_PID" 2>/dev/null
kill "$PARSER_PID" 2>/dev/null
sleep 1

# ---------------------------------------------------------------------------
# 4b. IMSI->IP map + canonical CSV path -- so a live ryu-manager process
# (telemetry/mobile_adapter.py's MobileNetworkAdapter, polled once per
# COLLECT_INTERVAL) actually picks up this run's results. Skipped
# entirely if SKIP_CONTROLLER_WIRING=1 (e.g. running this standalone,
# without caring about the Python controller side).
# ---------------------------------------------------------------------------

if [ "${SKIP_CONTROLLER_WIRING:-0}" -eq 0 ]; then
  UE_IP_MAP_CSV="${REPO_DIR}/config/ue_ip_map.csv"
  echo "imsi,ip" > "$UE_IP_MAP_CSV"
  grep "^\[UE_IP_MAP\] " "${OUT_DIR}/ns3.log" | sed 's/^\[UE_IP_MAP\] //' >> "$UE_IP_MAP_CSV"
  UE_COUNT="$(($(wc -l < "$UE_IP_MAP_CSV") - 1))"
  echo "[run_oran_e2_test] wrote ${UE_COUNT} IMSI->IP row(s) to ${UE_IP_MAP_CSV}"

  CANONICAL_CSV="/tmp/ddos_xapp_events.csv"
  if [ -f "${OUT_DIR}/ddos_xapp_events.csv" ]; then
    cp "${OUT_DIR}/ddos_xapp_events.csv" "$CANONICAL_CSV"
    echo "[run_oran_e2_test] copied this run's events to ${CANONICAL_CSV} (MobileNetworkAdapter's default path)"
  else
    : > "$CANONICAL_CSV"
    echo "[run_oran_e2_test] no events were produced this run -- cleared ${CANONICAL_CSV} so a live controller doesn't see stale data from a previous run"
  fi
fi

# ---------------------------------------------------------------------------
# 5. Summary
# ---------------------------------------------------------------------------

echo ""
echo "=================== SUMMARY ==================="
echo "logs: ${OUT_DIR}"
echo ""
echo "-- ns-3 PATCHED-DIAG lines --"
grep -i "PATCHED-DIAG" "${OUT_DIR}/ns3.log" || echo "(none)"
echo ""
echo "-- ns-3 SUBSCRIPTION/SETUP lines --"
grep -iE "SUBSCRIPTION|SETUP-RESPONSE|E2-SETUP" "${OUT_DIR}/ns3.log" || echo "(none)"
echo ""
echo "-- nearRT-RIC crash check --"
if grep -qiE "Assertion|Aborted|core dumped" "${OUT_DIR}/nearRT-RIC.log" 2>/dev/null; then
  echo "*** nearRT-RIC CRASHED -- see ${OUT_DIR}/nearRT-RIC.log"
  grep -iE "Assertion|Aborted|core dumped" "${OUT_DIR}/nearRT-RIC.log"
else
  echo "no crash detected"
fi
echo ""
echo "-- xApp KPM indications received --"
if [ -f "${OUT_DIR}/xapp_kpm_moni.log" ]; then
  COUNT="$(grep -c "KPM ind_msg latency" "${OUT_DIR}/xapp_kpm_moni.log")"
  echo "${COUNT} indication(s)"
else
  echo "(no xapp_kpm_moni.log -- did it ever start?)"
fi
echo ""
echo "-- parsed CSV rows --"
if [ -f "${OUT_DIR}/ddos_xapp_events.csv" ]; then
  wc -l "${OUT_DIR}/ddos_xapp_events.csv"
else
  echo "0 (no CSV file produced)"
fi
echo "================================================="
echo ""
echo "Full logs:"
echo "  ${OUT_DIR}/build.log"
echo "  ${OUT_DIR}/nearRT-RIC.log"
echo "  ${OUT_DIR}/ns3.log"
echo "  ${OUT_DIR}/xapp_kpm_moni.log"
echo "  ${OUT_DIR}/parser.log"
echo "  ${OUT_DIR}/ddos_xapp_events.csv"
