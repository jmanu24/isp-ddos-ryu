#!/usr/bin/env bash
#
# docs/peering-plan.md §2.2 -- reproduces the CONFIRMED PASS: a BGP
# FlowSpec discard route, announced by exabgp, installed by `flow`
# (github.com/hack3ric/flow) as a real nftables rule. This replaces
# deploy/spike_flowspec_frr.sh, which is kept in the repo only as
# documented negative evidence (FRR never installs the rule for real --
# see docs/peering-plan.md §2.1, FRRouting/frr#3160).
#
# Deliberately decoupled from the Mininet topology (topologies/
# star_topology.py): both exabgp and flow run inside one dedicated
# network namespace (exabgp-ns) on this VM, talking over its own
# loopback -- this tests the software capability in isolation before
# wiring it into r1's actual netns/interfaces. Unlike FRR, `flow` has
# no restriction against loopback/self peering (confirmed: the session
# established on the first attempt, no workarounds needed).
#
# Requires deploy/install_bgp_peering.sh to have run already.
#
# Usage:
#   sudo ./deploy/spike_flowspec_flow.sh            # run the spike
#   sudo ./deploy/spike_flowspec_flow.sh --cleanup   # stop flow/exabgp, remove the namespace

set -euo pipefail

NETNS=exabgp-ns
FIFO=/run/exabgp/flow-spike.in
EXABGP_CONF=/tmp/exabgp_flow_spike.conf
EXABGP_LOG=/tmp/exabgp_flow_spike.log
FLOW_LOG=/tmp/flow_spike.log
TEST_DST="198.51.100.99"   # TEST-NET-2 (RFC 5737) -- guaranteed non-routable, never a real host
FLOW_ADDR="127.0.0.1"
EXABGP_ADDR="127.0.0.2"

ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1" >&2; }
fail() { echo "  [FAIL] $1" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  fail "Correr como root (sudo) -- necesita namespaces de red y nftables."
fi

cleanup() {
  echo "== Limpieza =="
  pkill -9 -f "exabgp $EXABGP_CONF" 2>/dev/null && ok "exabgp detenido" || warn "exabgp no estaba corriendo"
  pkill -9 -f "flow run" 2>/dev/null && ok "flow detenido" || warn "flow no estaba corriendo"
  ip netns del "$NETNS" 2>/dev/null && ok "namespace $NETNS eliminado" || warn "namespace $NETNS no existía"
  rm -f "$FIFO" "$EXABGP_CONF" "$EXABGP_LOG" "$FLOW_LOG"
}

if [ "${1:-}" = "--cleanup" ]; then
  cleanup
  exit 0
fi

command -v flow   >/dev/null 2>&1 || fail "flow no encontrado -- correr deploy/install_bgp_peering.sh primero."
command -v exabgp >/dev/null 2>&1 || fail "exabgp no encontrado -- correr deploy/install_bgp_peering.sh primero."
command -v nft    >/dev/null 2>&1 || fail "nft (nftables) no encontrado."

echo "== 0. Preparando namespace aislado ($NETNS) =="
ip netns add "$NETNS" 2>/dev/null || ok "namespace $NETNS ya existía"
ip netns exec "$NETNS" ip link set lo up
mkdir -p /run/flow /run/exabgp
ok "namespace listo"

echo "== 1. Arrancando flow (AS 65001, escucha en $FLOW_ADDR:179) =="
pkill -9 -f "flow run" 2>/dev/null || true
rm -f "$FLOW_LOG"
ip netns exec "$NETNS" bash -c "nohup flow run -b ${FLOW_ADDR}:179 -l 65001 -r 65002 -i 10.99.99.1 > $FLOW_LOG 2>&1 &"
sleep 2
cat "$FLOW_LOG"
grep -q "listening" "$FLOW_LOG" || fail "flow no arrancó -- ver $FLOW_LOG arriba."
ok "flow escuchando"

echo "== 2. Arrancando exabgp como el otro extremo (AS 65002) =="
mkdir -p /run/exabgp
rm -f "$FIFO"
mkfifo "$FIFO"
chmod 666 "$FIFO"

# exabgp does NOT create or read this FIFO on its own -- the `process`
# block below runs `cat` against it, and exabgp treats that command's
# stdout as its command input.
cat > "$EXABGP_CONF" <<EOF
process spike {
    run /bin/cat $FIFO;
    encoder text;
}

neighbor $FLOW_ADDR {
    router-id $EXABGP_ADDR;
    local-address $EXABGP_ADDR;
    local-as 65002;
    peer-as 65001;

    family {
        ipv4 flow;
    }

    api {
        processes [ spike ];
    }
}
EOF

pkill -9 -f "exabgp $EXABGP_CONF" 2>/dev/null || true
rm -f "$EXABGP_LOG"
ip netns exec "$NETNS" bash -c "nohup exabgp $EXABGP_CONF > $EXABGP_LOG 2>&1 &"
sleep 5

echo "== 3. Verificando sesión BGP establecida (lado flow) =="
if grep -q "established" "$FLOW_LOG"; then
  ok "sesión BGP con exabgp establecida"
else
  warn "sesión BGP no confirmada en el log de flow -- log de exabgp:"
  tail -20 "$EXABGP_LOG" 2>/dev/null || true
  fail "no se puede continuar sin sesión BGP establecida -- revisar arriba antes de reintentar"
fi

echo "== 4. Anunciando ruta FlowSpec de descarte hacia $TEST_DST:80/tcp =="
echo "announce flow route { match { destination $TEST_DST/32; protocol tcp; destination-port =80; } then { discard; } }" > "$FIFO"
sleep 2

echo "== 5. Ruta recibida y estado de flow =="
ip netns exec "$NETNS" flow show

echo "== 6. Instalación real en el plano de datos (nftables, dentro del namespace) =="
ip netns exec "$NETNS" nft list ruleset

echo
echo "== RESULTADO (announce) =="
if ip netns exec "$NETNS" nft list ruleset 2>/dev/null | grep -q "$TEST_DST"; then
  ok "flow instaló una regla real de nftables para $TEST_DST (docs/peering-plan.md §2.2)."
else
  fail "la ruta aparece en 'flow show' (paso 5) pero no hay regla real de nftables (paso 6) -- \
esto NO coincide con el resultado ya confirmado el 2026-09-10/11; revisar si cambió la versión de flow instalada."
fi

echo "== 7. Retirando la ruta (withdraw) =="
echo "withdraw flow route { match { destination $TEST_DST/32; protocol tcp; destination-port =80; } then { discard; } }" > "$FIFO"
sleep 2

echo "== 8. Confirmando que la ruta y la regla real desaparecieron =="
echo "--- flow show ---"
ip netns exec "$NETNS" flow show
echo "--- nftables ---"
ip netns exec "$NETNS" nft list ruleset

echo
echo "== RESULTADO (withdraw) =="
if ip netns exec "$NETNS" nft list ruleset 2>/dev/null | grep -q "$TEST_DST"; then
  fail "la regla de nftables para $TEST_DST sigue presente después del withdraw -- retiro NO confirmado."
else
  ok "la regla de nftables para $TEST_DST fue removida -- ciclo announce/withdraw confirmado de punta a punta."
fi

echo
echo "== RESULTADO FINAL =="
echo "PASS -- ciclo completo announce -> instalación real -> withdraw -> remoción real,"
echo "confirmado (docs/peering-plan.md §2.2). Pendiente: integración dentro de la"
echo "topología Mininet real (ver §5/§6 del plan) y medición de efecto sobre tráfico."

echo
echo "Para limpiar: sudo ./deploy/spike_flowspec_flow.sh --cleanup"
