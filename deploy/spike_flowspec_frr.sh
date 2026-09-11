#!/usr/bin/env bash
#
# docs/peering-plan.md §2 -- standalone go/no-go spike for FRR's FlowSpec
# support: confirms (or refutes) that a FlowSpec route received from an
# external BGP speaker (exabgp) actually gets installed as a real
# iptables/ipset rule by FRR's bgpd (via its PBR integration), not just
# added to the BGP RIB. Per FRR's own FlowSpec docs, "FRR is a FlowSpec
# client only" -- rules cannot be originated from the CLI, they must
# come from an external speaker, which is exactly why exabgp is used
# here instead of injecting the route with `vtysh` directly.
#
# Deliberately decoupled from the Mininet topology (topologies/
# star_topology.py): both BGP speakers run on this VM's loopback
# (127.0.0.1 = FRR/AS65001, 127.0.0.2 = exabgp/AS65002), so this tests
# the software capability in isolation before wiring it into r1's
# actual netns/interfaces.
#
# Requires deploy/install_bgp_peering.sh to have run already.
#
# Usage:
#   sudo ./deploy/spike_flowspec_frr.sh            # run the spike
#   sudo ./deploy/spike_flowspec_frr.sh --cleanup   # stop exabgp, undo bgpd config

set -euo pipefail

FIFO=/run/exabgp/spike.in
EXABGP_CONF=/tmp/exabgp_spike.conf
EXABGP_LOG=/tmp/exabgp_spike.log
TEST_DST="198.51.100.99"   # TEST-NET-2 (RFC 5737) -- guaranteed non-routable, never a real host

ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1" >&2; }
fail() { echo "  [FAIL] $1" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  fail "Correr como root (sudo) -- necesita configurar FRR y leer iptables/ipset."
fi

cleanup() {
  echo "== Limpieza =="
  pkill -f "exabgp $EXABGP_CONF" 2>/dev/null && ok "exabgp detenido" || warn "exabgp no estaba corriendo"
  rm -f "$FIFO" "$EXABGP_CONF" "$EXABGP_LOG"
  vtysh -c "configure terminal" -c "router bgp 65001" -c "no neighbor 127.0.0.2 remote-as 65002" >/dev/null 2>&1 \
    && ok "configuración de bgpd revertida" || warn "no había configuración de bgpd que revertir"
}

if [ "${1:-}" = "--cleanup" ]; then
  cleanup
  exit 0
fi

command -v vtysh   >/dev/null 2>&1 || fail "FRR (vtysh) no encontrado -- correr deploy/install_bgp_peering.sh primero."
command -v exabgp  >/dev/null 2>&1 || fail "exabgp no encontrado -- correr deploy/install_bgp_peering.sh primero."
command -v iptables >/dev/null 2>&1 || fail "iptables no encontrado."
command -v ipset   >/dev/null 2>&1 || fail "ipset no encontrado -- correr deploy/install_bgp_peering.sh primero."

systemctl is-active --quiet frr || { echo "Arrancando frr..."; systemctl start frr; sleep 2; }
systemctl is-active --quiet frr || fail "frr no arrancó -- revisar: journalctl -u frr"

echo "== 1. Configurando bgpd (AS 65001, FlowSpec, peer 127.0.0.2) =="
vtysh -c "configure terminal" \
      -c "router bgp 65001" \
      -c "bgp router-id 127.0.0.1" \
      -c "neighbor 127.0.0.2 remote-as 65002" \
      -c "neighbor 127.0.0.2 description spike-exabgp" \
      -c "address-family ipv4 flowspec" \
      -c "neighbor 127.0.0.2 activate" \
      -c "local-install lo" \
      -c "exit-address-family"
ok "bgpd configurado"

echo "== 2. Arrancando exabgp como el otro extremo (AS 65002) =="
mkdir -p /run/exabgp
rm -f "$FIFO"
mkfifo "$FIFO"
chmod 666 "$FIFO"

# exabgp does NOT create or read this FIFO on its own -- the `process`
# block below runs `cat` against it, and exabgp treats that command's
# stdout as its command input. See the ExaBGP wiki, "Controlling
# ExaBGP: using a named PIPE".
cat > "$EXABGP_CONF" <<EOF
process spike {
    run /bin/cat $FIFO;
    encoder text;
}

neighbor 127.0.0.1 {
    router-id 127.0.0.2;
    local-address 127.0.0.2;
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

pkill -f "exabgp $EXABGP_CONF" 2>/dev/null || true
nohup exabgp "$EXABGP_CONF" > "$EXABGP_LOG" 2>&1 &
sleep 3
ok "exabgp arrancado (PID $!, log en $EXABGP_LOG)"

echo "== 3. Verificando sesión BGP establecida =="
if vtysh -c "show bgp neighbor 127.0.0.2" | grep -q "Established"; then
  ok "sesión BGP con exabgp establecida"
else
  warn "sesión BGP NO establecida -- log de exabgp:"
  tail -20 "$EXABGP_LOG" 2>/dev/null || true
  echo "--- show bgp neighbor 127.0.0.2 ---"
  vtysh -c "show bgp neighbor 127.0.0.2" | head -25
  fail "no se puede continuar sin sesión BGP establecida -- revisar arriba antes de reintentar"
fi

echo "== 4. Anunciando ruta FlowSpec de descarte hacia $TEST_DST:80/tcp =="
echo "announce flow route { match { destination $TEST_DST/32; protocol tcp; destination-port =80; } then { discard; } }" > "$FIFO"
sleep 2

echo "== 5. Ruta recibida por bgpd (RIB de FlowSpec) =="
vtysh -c "show bgp ipv4 flowspec"

echo "== 6. Instalación real en el plano de datos =="
echo "--- show pbr ipset ---"
vtysh -c "show pbr ipset" 2>&1 || warn "'show pbr ipset' no reconocido -- puede requerir habilitar pbrd en /etc/frr/daemons"
echo "--- show pbr iptable ---"
vtysh -c "show pbr iptable" 2>&1 || warn "'show pbr iptable' no reconocido"
echo "--- ipset list (sistema) ---"
ipset list 2>&1 || true
echo "--- iptables -S (sistema, filtrado a $TEST_DST) ---"
iptables -S 2>&1 | grep "$TEST_DST" || echo "(ninguna regla de iptables menciona $TEST_DST)"

echo
echo "== RESULTADO =="
if iptables -S 2>/dev/null | grep -q "$TEST_DST" || ipset list 2>/dev/null | grep -q "$TEST_DST"; then
  echo "PASS -- FRR instaló una regla real en el plano de datos para $TEST_DST."
  echo "FlowSpec es viable como mecanismo de mitigación de docs/peering-plan.md."
else
  echo "FAIL -- la ruta aparece en 'show bgp ipv4 flowspec' (paso 5) pero NO hay"
  echo "regla real de iptables/ipset para $TEST_DST (paso 6). FlowSpec no se está"
  echo "instalando en el plano de datos con esta versión/configuración de FRR --"
  echo "ver docs/peering-plan.md §2 ('si el spike falla', caer a RTBH)."
  echo
  echo "Antes de concluir FAIL definitivo, revisar:"
  echo "  - Si 'show pbr ipset'/'show pbr iptable' dieron [WARN] arriba, probar"
  echo "    habilitando pbrd: sed -i 's/^pbrd=no/pbrd=yes/' /etc/frr/daemons &&"
  echo "    systemctl restart frr, y volver a correr este script."
  echo "  - journalctl -u frr --since '2 min ago' | grep -i flowspec"
fi

echo
echo "Para limpiar: sudo ./deploy/spike_flowspec_frr.sh --cleanup"
