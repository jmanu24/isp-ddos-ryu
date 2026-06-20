#!/usr/bin/python3
"""
4 switches in a ring (s1-s2-s3-s4-s1), one host per switch, each host in
its own /24 subnet, plus a router (r1) with one interface on each switch
so all 4 subnets can reach each other.

A ring is a physical L2 loop. LearningSwitch (forwarding/learning_switch.py)
does not implement spanning tree or any other loop-prevention — broadcast
traffic (ARP) would circulate forever and storm the network. STP is
enabled directly via `ovs-vsctl set Bridge <sw> stp_enable=true` after
net.start() — OVSSwitch's `stp=True` constructor kwarg does NOT reliably
turn this on (confirmed: `ovs-appctl stp/show` showed nothing and the
ring stormed billions of packets in testing), so don't rely on it alone.
"""

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from mininet.node import Node
from mininet.link import TCLink
from mininet.cli import CLI


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

    print("*** Habilitando STP en cada bridge OVS (rompe el loop del anillo)")

    for s in switches:
        s.cmd(f'ovs-vsctl set Bridge {s.name} stp_enable=true')

    print("*** Configurando interfaces del router")

    for i in range(1, 5):
        r1.cmd(f'ip addr add 10.0.{i}.1/24 dev r1-eth{i - 1}')

    print("*** Tabla de rutas del router")
    print(r1.cmd('ip route'))

    print(
        "*** STP habilitado en cada switch — espera ~30-45s a que "
        "converja (verifica con 'ovs-appctl stp/show s1') antes de "
        "correr pingall o cualquier tráfico"
    )

    CLI(net)

    net.stop()


if __name__ == '__main__':
    topology()
