"""
Ad-hoc VM-side test for docs/peering-plan.md §5 -- fully self-contained
(announce + verify + withdraw + verify + teardown all happen inside
this one process, since r1's Mininet node/namespace only stays alive
as long as this script's Python process does).

Run as root: sudo python3 test_peering_topology.py
"""
import sys
import time

sys.path.insert(0, "/home/ubuntu/isp-ddos-ryu")

from topologies.star_topology import build_topology, add_central_server, _disable_rp_filter_star
from webtool.peering_ops import PeeringLifecycle, FLOW_LOG_PATH, EXABGP_LOG_PATH

TEST_DST = "198.51.100.99"
FIFO = "/run/exabgp/exabgp.in"

def announce_or_withdraw(verb):
    cmd = f'{verb} flow route {{ match {{ destination {TEST_DST}/32; protocol tcp; destination-port =80; }} then {{ discard; }} }}'
    with open(FIFO, "w") as f:
        f.write(cmd + "\n")

print("*** Building topology...")
net, r1, switches, hosts = build_topology()
add_central_server(r1)
_disable_rp_filter_star(r1, len(switches))

print("*** Starting PeeringLifecycle (flow on r1 + exabgp in root ns)...")
peering = PeeringLifecycle(r1)
ok = True
try:
    peering.start()
    print("*** Waiting 6s for the BGP session to establish...")
    time.sleep(6)
    print(open(FLOW_LOG_PATH).read())

    if "established" not in open(FLOW_LOG_PATH).read():
        print("*** FAIL: BGP session did not establish. exabgp log:")
        print(open(EXABGP_LOG_PATH).read())
        ok = False
    else:
        print(f"*** Announcing FlowSpec discard route for {TEST_DST}:80/tcp...")
        announce_or_withdraw("announce")
        time.sleep(2)

        print("*** nftables ruleset on r1 (real namespace, via r1.cmd) AFTER announce:")
        after_announce = r1.cmd("nft list ruleset")
        print(after_announce)

        print("*** Withdrawing the route...")
        announce_or_withdraw("withdraw")
        time.sleep(2)

        print("*** nftables ruleset on r1 AFTER withdraw:")
        after_withdraw = r1.cmd("nft list ruleset")
        print(after_withdraw)

        if TEST_DST in after_announce and TEST_DST not in after_withdraw:
            print(f"*** PASS: {TEST_DST} appeared in nftables after announce and disappeared after withdraw, inside the real r1.")
        else:
            print("*** FAIL: rule did not appear/disappear as expected -- see output above.")
            ok = False
finally:
    print("*** Tearing down (peering.stop() then net.stop())...")
    peering.stop()
    net.stop()

sys.exit(0 if ok else 1)
