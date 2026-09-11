#!/usr/bin/python3
"""
Star topology: 4 switches (s1-s4), each connected ONLY to a central
router r1 -- no switch-switch links at all, unlike topologies/
ring_topology.py's ring. A star has no physical L2 loop, so unlike that
file, RSTP is neither needed nor enabled here: broadcast/ARP traffic has
exactly one path to anywhere, nothing to storm.

Each switch gets 3 real hosts, one per controller domain, all in that
switch's own /24 (10.0.<i>.0/24, r1's gateway at .1 -- same convention
ring_topology.py already uses):

  ent_<i>   (enterprise) -- 10.0.<i>.10/24, a plain host. Real,
            unspoofed traffic from/to it is already exactly what the
            native OpenFlow "enterprise" detection pipeline handles --
            no telemetry simulation needed.
  gnb_<i>   (mobile)     -- 10.0.<i>.20/24, represents ONE gNB (base
            station) with its own gNB ID. UEs "behind" it are NOT this
            address -- see simulation/gnb_pool.py, which anchors
            spoofed-source hping3 UEs to this physical host, one gNB
            per switch instead of round-robining across a shared host
            pool the way simulation/ue_traffic_generator.py's
            interactive mode does.
  fixed_<i> (broadband)  -- 10.0.<i>.30/24, a real host present for the
            topology graph/UI only -- the actual BNGBlaster traffic
            never reaches it directly (see attach_bng_gateway_to_r1
            below); r1 itself is the BNG's gateway.

Also adds a dummy "central server" interface directly on r1
(CENTRAL_SERVER_IP) that every one of the 12 hosts can already reach via
their existing default route through r1, with zero extra routes needed
-- the intended target for auto-generated benign/baseline traffic.
"""

import subprocess

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI

from topologies.ring_topology import LinuxRouter


CENTRAL_SERVER_IFACE = "r1-central0"
CENTRAL_SERVER_IP = "10.99.0.1"
CENTRAL_SERVER_CIDR = "10.99.0.1/24"

# BGP Peering domain uplink (see docs/peering-plan.md §5): a veth pair
# between the ROOT namespace (where webtool/orchestrator.py's exabgp
# subprocess runs, alongside the Ryu controller itself) and r1's own
# namespace (where `flow` runs, installing FlowSpec routes as real
# nftables rules). 10.98.0.0/24 -- distinct from 10.50.0.0/24 (BNG),
# 10.60.0.0/16 (mobile UEs), 10.61.x.0/24 (BNG sessions) and
# 10.99.0.0/24 (central server), all already in use elsewhere in this
# topology.
PEERING_UPLINK_IFACE_ROOT = "veth-peering0"
PEERING_UPLINK_IFACE_R1 = "veth-peering1"
PEERING_UPLINK_ROOT_IP = "10.98.0.1"
PEERING_UPLINK_ROOT_CIDR = "10.98.0.1/24"
PEERING_UPLINK_R1_IP = "10.98.0.2"
PEERING_UPLINK_R1_CIDR = "10.98.0.2/24"

# BGP Peering domain's external/upstream side (docs/peering-plan.md §5):
# a real Mininet host (peer_ext) linked DIRECTLY to r1 -- not through
# any switch -- representing traffic entering from outside the SP
# network, the same conceptual role ent_i/gnb_i/fixed_i each play for
# their own domain. softflowd watches r1's side of this specific link
# (deploy/install_bgp_peering.sh / webtool/peering_ops.py); test attack
# traffic for the peering domain should originate from peer_ext.
# 10.97.0.0/24 -- distinct from every other reserved range in this file.
EXTERNAL_PEER_IFACE_R1 = "r1-ext0"
EXTERNAL_PEER_IP = "10.97.0.2"
EXTERNAL_PEER_CIDR = "10.97.0.2/24"
R1_EXTERNAL_IP = "10.97.0.1"
R1_EXTERNAL_CIDR = "10.97.0.1/24"

ROLE_ENTERPRISE = "enterprise"
ROLE_MOBILE_GNB = "mobile_gnb"
ROLE_FIXED = "fixed"


def build_topology(num_switches: int = 4):
    """
    Builds r1 + num_switches OVS switches, each linked ONLY to r1, with
    3 hosts per switch (one per domain). Calls net.start() internally
    (same contract simulation/ue_traffic_generator.py's own
    build_topology() already uses) but does NOT call CLI(net)/net.stop()
    -- the caller owns the net's lifecycle.

    Returns (net, r1, switches, hosts) where hosts is
    {i: {"enterprise": Host, "mobile_gnb": Host, "fixed": Host}}
    for i in 1..num_switches.
    """
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink)

    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    switches = [
        net.addSwitch(f's{i}', protocols='OpenFlow13')
        for i in range(1, num_switches + 1)
    ]

    r1 = net.addHost('r1', cls=LinuxRouter)

    # Router links first, in switch order, so r1-eth<k> deterministically
    # maps to switch k+1 -- same ordering convention ring_topology.py's
    # own topology() relies on for its identical r1.cmd('ip addr add ...
    # dev r1-eth{i-1}') pattern below.
    for s in switches:
        net.addLink(r1, s)

    hosts = {}
    for i in range(1, num_switches + 1):
        subnet = f'10.0.{i}'
        ent = net.addHost(f'ent_{i}', ip=f'{subnet}.10/24', defaultRoute=f'via {subnet}.1')
        gnb = net.addHost(f'gnb_{i}', ip=f'{subnet}.20/24', defaultRoute=f'via {subnet}.1')
        fixed = net.addHost(f'fixed_{i}', ip=f'{subnet}.30/24', defaultRoute=f'via {subnet}.1')

        net.addLink(ent, switches[i - 1])
        net.addLink(gnb, switches[i - 1])
        net.addLink(fixed, switches[i - 1])

        hosts[i] = {ROLE_ENTERPRISE: ent, ROLE_MOBILE_GNB: gnb, ROLE_FIXED: fixed}

    net.start()

    for i in range(1, num_switches + 1):
        r1.cmd(f'ip addr add 10.0.{i}.1/24 dev r1-eth{i - 1}')

    return net, r1, switches, hosts


def add_central_server(r1) -> None:
    """A dummy interface directly on r1 -- the destination for
    auto-generated benign/baseline traffic. Never a valid attack
    target (see simulation/gnb_pool.py's UE benign-target reasoning --
    an attack and a benign loop sharing one dst_ip breaks the
    controller's presence-based unblock signal)."""
    r1.cmd(f'ip link add name {CENTRAL_SERVER_IFACE} type dummy')
    r1.cmd(f'ip link set {CENTRAL_SERVER_IFACE} up')
    r1.cmd(f'ip addr add {CENTRAL_SERVER_CIDR} dev {CENTRAL_SERVER_IFACE}')
    print(f"*** Servidor central {CENTRAL_SERVER_IP} agregado a r1 ({CENTRAL_SERVER_IFACE})")


def _disable_rp_filter_star(r1, num_switches: int) -> None:
    """
    Same purpose as simulation/ue_traffic_generator.py's own
    _disable_rp_filter (duplicated, not imported -- that module already
    follows the same no-cross-import convention for ring_topology.py):
    UEs behind each gNB live in 10.60.<i>.0/24, a subnet r1 has no real
    route for. Without this, r1's reverse-path filter silently drops
    every spoofed UE packet as martian, and mobile traffic would
    produce zero observable results with no visible error anywhere.
    Must run before any UE hping3 process starts. Iterates
    range(num_switches), not a hardcoded range(4), so it stays correct
    if the star is ever built with a different switch count.
    """
    r1.cmd('sysctl -w net.ipv4.conf.all.rp_filter=0')
    r1.cmd('sysctl -w net.ipv4.conf.default.rp_filter=0')
    for i in range(num_switches):
        r1.cmd(f'sysctl -w net.ipv4.conf.r1-eth{i}.rp_filter=0')
    print(f"*** rp_filter deshabilitado en r1 ({num_switches} interfaces) -- "
          f"trafico UE spoofed (10.60.0.0/16) sera reenviado")


def attach_bng_gateway_to_r1(
    r1, network_peer: str = "veth-n-peer", addr_cidr: str = "10.50.0.1/24"
) -> None:
    """
    Gives r1 a genuine 5th real interface toward BNGBlaster's network
    side, so r1 itself is the BNG's gateway -- instead of deploy/
    setup_bng_netns.sh's --bridge-into-mininet flag, which enslaves
    veth-n-peer to an OVS bridge port (that mechanism stays untouched
    and independently usable with the ring topology; this is a
    separate, simpler code path for the star).

    An OVS bridge port can't hold an IP/answer ARP directly once
    enslaved -- moving the interface into r1's own network namespace
    instead avoids that problem entirely: r1 is a genuine Linux
    process (Mininet nodes run inside a fresh netns via `mnexec -a`,
    not a named `ip netns`), so `ip link set <if> netns <r1.pid>` is
    the correct, standard way to attach a pre-existing host interface
    to it (the same technique Mininet's own moveIntf() helper uses).
    Once moved, r1's existing ip_forward=1 (see LinuxRouter) routes
    between this and every other directly-connected subnet natively,
    no static routes needed -- BNG's 10.50.0.0/24 becomes just another
    one of r1's own subnets.

    Precondition: deploy/setup_bng_netns.sh has already run (creates
    network_peer in the ROOT namespace with addr_cidr already assigned
    to it there, its own default behavior). Must be called after
    build_topology() (i.e. after net.start()), so r1.pid is valid.
    """
    # Best-effort: the address may or may not still be there depending
    # on how setup_bng_netns.sh was invoked -- absence isn't an error.
    subprocess.run(["ip", "addr", "del", addr_cidr, "dev", network_peer], check=False)

    subprocess.run(["ip", "link", "set", network_peer, "netns", str(r1.pid)], check=True)

    r1.cmd(f'ip link set {network_peer} up')
    r1.cmd(f'ip addr add {addr_cidr} dev {network_peer}')
    print(f"*** {network_peer} movido al namespace de r1 ({addr_cidr}) -- "
          f"r1 es ahora el gateway de BNGBlaster")


def attach_external_peer(net, r1):
    """
    Adds peer_ext, a real Mininet host linked directly to r1 (no
    switch in between), representing the BGP Peering domain's
    external/upstream side (docs/peering-plan.md §5) -- see
    EXTERNAL_PEER_IFACE_R1's module-level comment for why.

    Dynamic host+link addition AFTER net.start() -- Mininet supports
    this (net.addHost()/net.addLink() aren't tied to the start()
    call), which keeps build_topology()'s own signature and every
    existing caller (webtool/orchestrator.py, validate_phase1.py,
    validate_peering.py) unchanged rather than growing its return
    tuple. Explicit intfName1/intfName2 avoid having to guess which
    of r1's interfaces Mininet auto-assigned to the new link.

    Returns the peer_ext Host so the caller can launch attack traffic
    from it later.
    """
    peer_ext = net.addHost('peer_ext', ip=EXTERNAL_PEER_CIDR, defaultRoute=f'via {R1_EXTERNAL_IP}')
    net.addLink(r1, peer_ext, intfName1=EXTERNAL_PEER_IFACE_R1, intfName2='peer_ext-eth0')

    r1.cmd(f'ip link set {EXTERNAL_PEER_IFACE_R1} up')
    r1.cmd(f'ip addr add {R1_EXTERNAL_CIDR} dev {EXTERNAL_PEER_IFACE_R1}')
    peer_ext.cmd('ip link set peer_ext-eth0 up')

    print(f"*** peer_ext ({EXTERNAL_PEER_IP}) agregado -- enlazado directo a r1 "
          f"via {EXTERNAL_PEER_IFACE_R1} ({R1_EXTERNAL_IP})")
    return peer_ext


def attach_peering_uplink_to_r1(r1) -> None:
    """
    Gives r1 a genuine interface reachable from the ROOT namespace, for
    the BGP Peering domain (docs/peering-plan.md §5): webtool/
    orchestrator.py's `exabgp` subprocess (root namespace, alongside the
    Ryu controller itself) needs a real routed path to `flow` (started
    inside r1's own namespace by this same orchestrator, see
    webtool/peering_ops.py), since `flow` is the process that actually
    installs FlowSpec routes as nftables rules on r1.

    Same veth + move-into-r1's-pid-namespace technique as
    attach_bng_gateway_to_r1 above -- see that function's docstring for
    why this is the correct way to attach a ROOT-namespace interface to
    a Mininet node (which runs in a `mnexec -a`-managed namespace, not a
    named `ip netns`). Must be called after build_topology() (i.e.
    after net.start()), so r1.pid is valid.
    """
    subprocess.run(
        ["ip", "link", "add", PEERING_UPLINK_IFACE_ROOT, "type", "veth",
         "peer", "name", PEERING_UPLINK_IFACE_R1],
        check=True,
    )
    subprocess.run(
        ["ip", "addr", "add", PEERING_UPLINK_ROOT_CIDR, "dev", PEERING_UPLINK_IFACE_ROOT],
        check=True,
    )
    subprocess.run(["ip", "link", "set", PEERING_UPLINK_IFACE_ROOT, "up"], check=True)

    subprocess.run(
        ["ip", "link", "set", PEERING_UPLINK_IFACE_R1, "netns", str(r1.pid)],
        check=True,
    )
    r1.cmd(f'ip link set {PEERING_UPLINK_IFACE_R1} up')
    r1.cmd(f'ip addr add {PEERING_UPLINK_R1_CIDR} dev {PEERING_UPLINK_IFACE_R1}')
    print(f"*** {PEERING_UPLINK_IFACE_ROOT}/{PEERING_UPLINK_IFACE_R1} enlazados -- "
          f"r1 alcanzable en {PEERING_UPLINK_R1_IP} desde el namespace raiz "
          f"({PEERING_UPLINK_ROOT_IP})")


def detach_peering_uplink(root_iface: str = PEERING_UPLINK_IFACE_ROOT) -> None:
    """
    Deletes the veth pair from the ROOT namespace side -- deleting either
    end of a veth pair removes both, same convention as net.stop() itself
    tearing down Mininet's own links. Best-effort: the interface may
    already be gone if r1's own namespace was torn down first.
    """
    subprocess.run(["ip", "link", "del", root_iface], check=False)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attach-bng", action="store_true",
                         help="also attach BNGBlaster's veth-n-peer to r1 "
                              "(deploy/setup_bng_netns.sh must already have run)")
    args = parser.parse_args()

    net, r1, switches, hosts = build_topology()
    add_central_server(r1)
    _disable_rp_filter_star(r1, len(switches))

    if args.attach_bng:
        attach_bng_gateway_to_r1(r1)

    print("*** Tabla de rutas del router")
    print(r1.cmd('ip route'))

    CLI(net)

    net.stop()
