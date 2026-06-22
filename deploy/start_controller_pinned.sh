#!/usr/bin/env bash
#
# Launches ryu-manager pinned to a dedicated set of CPU cores, so the
# controller's own packet-in/detection/mitigation work never competes for
# CPU time with OVS's switch processing or the attack tools running inside
# Mininet hosts — all three were sharing the same core pool, which is the
# likely cause of switches dropping/reconnecting under heavy flood load
# (ovs-vswitchd starved of CPU long enough to miss the controller's
# keepalives).
#
# Core layout for a 16-core box (CONTROLLER_CORES below) — adjust the
# ranges if your testbed has a different core count:
#   0-1   : left free for the OS / Mininet's own bookkeeping
#   2-5   : ryu-manager (this script)
#   6-9   : OVS (see deploy/pin_ovs_affinity.sh — run that separately,
#           after switches exist)
#   10-15 : Mininet hosts / attack tools — prefix manually inside the
#           mininet CLI, e.g.: h1 taskset -c 10-15 hping3 -S --flood h4
#
# Usage:
#   ./deploy/start_controller_pinned.sh [extra ryu-manager args]

set -euo pipefail

CONTROLLER_CORES="${CONTROLLER_CORES:-2-5}"

cd "$(dirname "$0")/.."

echo "*** Lanzando ryu-manager fijado a cores ${CONTROLLER_CORES}"

exec taskset -c "$CONTROLLER_CORES" \
    env PYTHONPATH="$PWD" \
    ryu-manager --observe-links controller/ryu_controller_2.py "$@"
