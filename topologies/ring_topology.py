#!/usr/bin/python3
"""
4 switches in a ring (s1-s2-s3-s4-s1), one host per switch, each host in
its own /24 subnet.

A ring is a physical L2 loop. LearningSwitch (forwarding/learning_switch.py)
does not implement spanning tree or any other loop-prevention — broadcast
traffic (ARP) would circulate forever and storm the network. STP is
enabled at the OVS level instead (stp=True per switch), independent of the
controller, to block one ring link until a topology change requires it.

Hosts are on different subnets with no default gateway configured, since
no router is part of this topology — only direct host-to-host traffic on
the same switch (or broadcast/ARP across the ring) is expected to work.
Add a routing host (see topologies seen in l3.py-style scripts) if
cross-subnet routing is needed later.
"""

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI


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
        net.addSwitch(f's{i}', protocols='OpenFlow13', stp=True)
        for i in range(1, 5)
    ]

    print("*** Agregando hosts (una subred distinta por switch)")

    hosts = [
        net.addHost(f'h{i}', ip=f'10.0.{i}.10/24')
        for i in range(1, 5)
    ]

    print("*** Conectando cada host a su switch")

    for h, s in zip(hosts, switches):
        net.addLink(h, s)

    print("*** Cerrando el anillo: s1-s2-s3-s4-s1")

    for a, b in zip(switches, switches[1:] + switches[:1]):
        net.addLink(a, b)

    print("*** Iniciando red")

    net.start()

    print(
        "*** STP habilitado en cada switch — puede tardar ~30s en "
        "converger antes de que el tráfico fluya por el anillo"
    )

    CLI(net)

    net.stop()


if __name__ == '__main__':
    topology()
