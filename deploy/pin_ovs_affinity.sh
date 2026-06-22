#!/usr/bin/env bash
#
# Pins the already-running OVS processes (ovs-vswitchd, ovsdb-server) to a
# dedicated set of CPU cores, separate from the controller
# (deploy/start_controller_pinned.sh) and from Mininet hosts/attack tools.
# Run this AFTER starting the topology (net.start() already launched OVS),
# since it operates on live PIDs via taskset -cp, not via a wrapped launch
# command like the controller script — OVS is started by Mininet/ovs-ctl,
# not directly by us.
#
# See deploy/start_controller_pinned.sh for the full core layout rationale
# on a 16-core box.
#
# Usage (after `sudo python3 topologies/ring_topology.py` has started the
# network, in another terminal):
#   sudo ./deploy/pin_ovs_affinity.sh

set -euo pipefail

OVS_CORES="${OVS_CORES:-6-9}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root (sudo $0) — taskset -cp on another user's process needs it." >&2
    exit 1
fi

pinned_any=false

for proc in ovs-vswitchd ovsdb-server; do
    pids="$(pgrep -x "$proc" || true)"

    if [ -z "$pids" ]; then
        echo "*** $proc no esta corriendo todavia (¿ya iniciaste la topologia?) — omitido"
        continue
    fi

    for pid in $pids; do
        taskset -cp "$OVS_CORES" "$pid"
        pinned_any=true
    done
done

if [ "$pinned_any" = false ]; then
    echo "*** Nada que fijar — inicia la topologia primero y vuelve a correr este script."
    exit 1
fi

echo "*** OVS fijado a cores ${OVS_CORES}"
