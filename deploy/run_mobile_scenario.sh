#!/usr/bin/env bash
#
# End-to-end runner for the mobile-domain O-RAN scenario, real-traffic
# version: controller + real Mininet ring topology + real hping3 UE
# traffic (simulation/ue_traffic_generator.py) + nftables-based KPM
# monitor (simulation/ue_kpm_monitor.py), all the way through the real
# detection/mitigation pipeline. Requires root and Linux (Mininet +
# hping3 raw sockets, nft) -- run this on the Ubuntu test VM.
#
# What this does, in order:
#   1. Launches ryu-manager (controller/ryu_controller_2.py) in the
#      background, unless --no-controller is given (e.g. it's already
#      running from another terminal).
#   2. Runs simulation/ue_traffic_generator.py in the foreground, which
#      itself builds topologies/ring_topology.py's ring, launches
#      simulation/ue_kpm_monitor.py on r1, and drives every UE's real
#      hping3 traffic for the chosen scenario.
#   3. On exit (Ctrl-C, natural end, or Mininet CLI exit for --duration
#      0): stops the controller it started. The topology, monitor, and
#      hping3 processes are torn down by ue_traffic_generator.py itself.
#      /tmp/ddos_xapp_events.csv and the controller log are never
#      deleted -- they're output, not configuration.
#
# Usage:
#   sudo ./deploy/run_mobile_scenario.sh udp_flood
#   sudo ./deploy/run_mobile_scenario.sh syn_flood --duration 90
#   sudo ./deploy/run_mobile_scenario.sh icmp_flood --duration 90
#   sudo ./deploy/run_mobile_scenario.sh distributed_syn --duration 90
#   sudo ./deploy/run_mobile_scenario.sh low_slow --duration 120
#   sudo ./deploy/run_mobile_scenario.sh udp_flood --no-controller
#   sudo ./deploy/run_mobile_scenario.sh udp_flood --duration 0   # drops into the Mininet CLI

set -euo pipefail

cd "$(dirname "$0")/.."

SCENARIOS=(udp_flood syn_flood icmp_flood distributed_syn low_slow)
SCENARIO=""
DURATION=90
START_CONTROLLER=1
EXTRA_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --no-controller) START_CONTROLLER=0; shift ;;
    -h|--help) sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)
      if [ -z "$SCENARIO" ]; then SCENARIO="$1"; shift; else EXTRA_ARGS+=("$1"); shift; fi
      ;;
  esac
done

if [ -z "$SCENARIO" ]; then
  echo "uso: $0 <escenario> [--duration N] [--no-controller]" >&2
  echo "escenarios: ${SCENARIOS[*]}" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: corre esto como root (sudo) -- Mininet/hping3 necesitan sockets raw." >&2
  exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "ERROR: Mininet solo corre en Linux -- corre esto en la VM Ubuntu, no en macOS." >&2
  exit 1
fi

for bin in hping3 nft; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "ERROR: '$bin' no esta instalado." >&2
    exit 1
  fi
done

CONTROLLER_PID=""
cleanup() {
  if [ -n "$CONTROLLER_PID" ]; then
    echo ""
    echo "== Deteniendo ryu-manager (pid ${CONTROLLER_PID}) =="
    kill "$CONTROLLER_PID" 2>/dev/null || true
    wait "$CONTROLLER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if [ "$START_CONTROLLER" -eq 1 ]; then
  echo "== 1. Levantando el controlador (ryu-manager) =="
  PYTHONPATH="$PWD" ryu-manager --observe-links controller/ryu_controller_2.py \
    > /tmp/mobile_scenario_controller.log 2>&1 &
  CONTROLLER_PID=$!
  echo "  [OK] ryu-manager corriendo (pid ${CONTROLLER_PID}), log en /tmp/mobile_scenario_controller.log"
  sleep 3
else
  echo "== 1. Omitido (--no-controller) -- asume que ya hay un controlador corriendo =="
fi

echo "== 2. Corriendo el escenario mobile '${SCENARIO}' (duracion ${DURATION}s) =="
python3 simulation/ue_traffic_generator.py \
  --scenario "$SCENARIO" \
  --duration "$DURATION" \
  "${EXTRA_ARGS[@]}"

echo ""
echo "*** Escenario '${SCENARIO}' terminado."
[ "$START_CONTROLLER" -eq 1 ] && echo "    Revisa /tmp/mobile_scenario_controller.log para DETECTION/MITIGATION del controlador."
echo "    Telemetria cruda en /tmp/ddos_xapp_events.csv"
