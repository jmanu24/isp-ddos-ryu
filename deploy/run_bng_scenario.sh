#!/usr/bin/env bash
#
# End-to-end runner: from a fresh checkout to a live BNGBlaster attack
# scenario flowing through the real controller pipeline (telemetry ->
# correlation -> detection -> decision -> orchestration -> BNGBlaster
# native mitigation). Linux-only (BNGBlaster needs raw sockets) -- run
# this on the Ubuntu test VM, not on the macOS dev machine.
#
# What this does, in order:
#   1. (skip if already done) ./deploy/install_bngblaster.sh
#   2. (skip if already done) ./deploy/setup_bng_netns.sh
#   3. Launches ryu-manager (controller/ryu_controller_2.py) in the
#      background, unless --no-controller is given (e.g. it's already
#      running from another terminal)
#   4. Runs simulation/bng_traffic_simulator.py for the chosen scenario
#      in the foreground, so you see its own [BNG] log lines live
#   5. On exit (Ctrl-C or natural end), stops the controller it started
#      and leaves the netns/dnsmasq setup in place (re-run with
#      --teardown-network to remove it)
#
# Usage:
#   sudo ./deploy/run_bng_scenario.sh syn_flood
#   sudo ./deploy/run_bng_scenario.sh udp_flood --duration 90
#   sudo ./deploy/run_bng_scenario.sh icmp_flood
#   sudo ./deploy/run_bng_scenario.sh distributed_syn_flood
#   sudo ./deploy/run_bng_scenario.sh low_and_slow --duration 120
#   sudo ./deploy/run_bng_scenario.sh syn_flood --no-controller
#   sudo ./deploy/run_bng_scenario.sh --teardown-network
#
# Must run as root (or with sudo) -- BNGBlaster needs raw sockets and
# the netns setup needs to create interfaces.

set -euo pipefail

cd "$(dirname "$0")/.."

SCENARIOS=(syn_flood udp_flood icmp_flood distributed_syn_flood low_and_slow)
SCENARIO=""
DURATION=60
TICK=0.5    # matches config/settings.py's COLLECT_INTERVAL by default
TARGET_IP="10.0.2.10"
START_CONTROLLER=1
TEARDOWN_NETWORK=0
EXTRA_SIM_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --teardown-network) TEARDOWN_NETWORK=1; shift ;;
    --duration) DURATION="$2"; shift 2 ;;
    --tick) TICK="$2"; shift 2 ;;
    --target-ip) TARGET_IP="$2"; shift 2 ;;
    --no-controller) START_CONTROLLER=0; shift ;;
    -h|--help) sed -n '2,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)
      if [ -z "$SCENARIO" ]; then SCENARIO="$1"; shift; else EXTRA_SIM_ARGS+=("$1"); shift; fi
      ;;
  esac
done

if [ "$TEARDOWN_NETWORK" -eq 1 ]; then
  exec ./deploy/setup_bng_netns.sh --teardown
fi

if [ -z "$SCENARIO" ]; then
  echo "uso: $0 <escenario> [--duration N] [--tick N] [--target-ip IP] [--no-controller]" >&2
  echo "escenarios: ${SCENARIOS[*]}" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: corre esto como root (sudo) -- BNGBlaster necesita sockets raw." >&2
  exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "ERROR: BNGBlaster solo corre en Linux -- corre esto en la VM Ubuntu, no en macOS." >&2
  exit 1
fi

echo "== 1. Verificando instalación de BNGBlaster =="
if ! command -v bngblaster >/dev/null 2>&1; then
  echo "  -> bngblaster no encontrado, instalando..."
  ./deploy/install_bngblaster.sh
else
  echo "  [OK] bngblaster ya instalado en $(command -v bngblaster)"
fi

echo "== 2. Verificando red (veth + dnsmasq) =="
if ! ip link show veth-a >/dev/null 2>&1 || ! ip link show veth-n >/dev/null 2>&1; then
  echo "  -> interfaces no encontradas, configurando..."
  ./deploy/setup_bng_netns.sh
else
  echo "  [OK] veth-a/veth-n ya existen"
fi

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
  echo "== 3. Levantando el controlador (ryu-manager) =="
  PYTHONPATH="$PWD" ryu-manager --observe-links controller/ryu_controller_2.py \
    > /tmp/bng_scenario_controller.log 2>&1 &
  CONTROLLER_PID=$!
  echo "  [OK] ryu-manager corriendo (pid ${CONTROLLER_PID}), log en /tmp/bng_scenario_controller.log"
  sleep 3
else
  echo "== 3. Omitido (--no-controller) -- asume que ya hay un controlador corriendo =="
fi

echo "== 4. Corriendo el escenario '${SCENARIO}' (duración ${DURATION}s) =="
python3 simulation/bng_traffic_simulator.py \
  --scenario "$SCENARIO" \
  --target-ip "$TARGET_IP" \
  --duration "$DURATION" \
  --tick "$TICK" \
  "${EXTRA_SIM_ARGS[@]}"

echo ""
echo "*** Escenario '${SCENARIO}' terminado."
[ "$START_CONTROLLER" -eq 1 ] && echo "    Revisa /tmp/bng_scenario_controller.log para DETECTION/MITIGATION del controlador."
echo "    Telemetría cruda en /tmp/ddos_bng_events.csv"
