#!/usr/bin/python3
"""
4 switches in a ring (s1-s2-s3-s4-s1), one host per switch, each host in
its own /24 subnet, plus a router (r1) with one interface on each switch
so all 4 subnets can reach each other.

A ring is a physical L2 loop. LearningSwitch (forwarding/learning_switch.py)
does not implement spanning tree or any other loop-prevention — broadcast
traffic (ARP) would circulate forever and storm the network. RSTP (802.1w)
is enabled directly via `ovs-vsctl set Bridge <sw> rstp_enable=true` after
net.start() — OVSSwitch's `stp=True` constructor kwarg does NOT reliably
turn even classic STP on (confirmed: `ovs-appctl stp/show` showed nothing
and the ring stormed billions of packets in testing), so don't rely on it.
RSTP converges in a couple of seconds via its proposal/agreement handshake
instead of classic STP's fixed ~30-50s listening/learning timers, so the
CLI unblocks much sooner.

CPU isolation: on a multi-core testbed, launch the controller via
deploy/start_controller_pinned.sh (not ryu-manager directly) and run
deploy/pin_ovs_affinity.sh once this topology is up, so OVS and the
controller never compete for CPU with each other or with attack traffic
under heavy flood load — that contention is what causes switches to drop
their controller connection and reconnect mid-attack. Once both are
pinned, run attack tools from this CLI prefixed with taskset on the
cores deploy/start_controller_pinned.sh left for Mininet (10-15 on a
16-core box), e.g.:
    mininet> h1 taskset -c 10-15 hping3 -S --flood h4
"""

import time

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from mininet.node import Node
from mininet.link import TCLink
from mininet.cli import CLI


# RSTP port states before settling on a stable role. While ANY port on ANY
# switch is still LEARNING, the ring isn't safe yet — broadcasts could
# still loop. DISCARDING and FORWARDING are the stable end states (RSTP
# has no separate listening/blocking phase the way classic STP does, which
# is exactly why it converges so much faster).
_RSTP_TRANSITIONAL_STATES = ("LEARNING",)


def _rstp_converged(switches):
    for s in switches:
        output = s.cmd(f'ovs-appctl rstp/show {s.name}').upper()
        if any(state in output for state in _RSTP_TRANSITIONAL_STATES):
            return False
    return True


def wait_for_rstp_convergence(switches, timeout=30, poll_interval=1):
    """
    Block until every switch's RSTP ports have left their transitional
    states — i.e. until the ring has a loop-free spanning tree and it's
    actually safe to send traffic. Returns without granting CLI access
    otherwise; the caller (topology()) only calls CLI(net) after this
    returns True.
    """
    print("*** Esperando convergencia de RSTP (no se habilitara la CLI hasta entonces)...")

    start = time.time()

    while time.time() - start < timeout:
        if _rstp_converged(switches):
            print(f"*** RSTP convergido en {time.time() - start:.1f}s")
            return True
        time.sleep(poll_interval)

    print(
        f"*** ADVERTENCIA: RSTP no convergio en {timeout}s — revisa "
        "'ovs-appctl rstp/show <switch>' manualmente. Continuando de "
        "todas formas para no bloquear la sesion indefinidamente."
    )
    return False


class LinuxRouter(Node):

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()


def topology():

    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink
    )

    print("*** Agregando controlador")

    net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    print("*** Agregando switches (anillo)")

    switches = [
        net.addSwitch(f's{i}', protocols='OpenFlow13')
        for i in range(1, 5)
    ]

    print("*** Agregando router")

    r1 = net.addHost('r1', cls=LinuxRouter)

    print("*** Agregando hosts (una subred distinta por switch)")

    hosts = [
        net.addHost(
            f'h{i}',
            ip=f'10.0.{i}.10/24',
            defaultRoute=f'via 10.0.{i}.1'
        )
        for i in range(1, 5)
    ]

    print("*** Conectando cada host a su switch")

    for h, s in zip(hosts, switches):
        net.addLink(h, s)

    print("*** Conectando el router a cada switch (una interfaz por subred)")

    for s in switches:
        net.addLink(r1, s)

    print("*** Cerrando el anillo: s1-s2-s3-s4-s1")

    for a, b in zip(switches, switches[1:] + switches[:1]):
        net.addLink(a, b)

    print("*** Iniciando red")

    net.start()

    print("*** Habilitando RSTP en cada bridge OVS (rompe el loop del anillo)")

    for s in switches:
        s.cmd(f'ovs-vsctl set Bridge {s.name} rstp_enable=true')

    print("*** Configurando interfaces del router")

    for i in range(1, 5):
        r1.cmd(f'ip addr add 10.0.{i}.1/24 dev r1-eth{i - 1}')

    print("*** Tabla de rutas del router")
    print(r1.cmd('ip route'))

    wait_for_rstp_convergence(switches)

    CLI(net)

    net.stop()


if __name__ == '__main__':
    topology()
