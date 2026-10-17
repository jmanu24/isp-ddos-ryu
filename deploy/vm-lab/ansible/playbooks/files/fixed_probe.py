"""Probe traffic for the fixed-domain validation, run inside a subscriber's
network namespace on `suscriptor`.

  fixed_probe.py udp DST PORT PPS SECS   -> UDP datagrams at PPS
  fixed_probe.py syn DST PORT PPS SECS   -> TCP connection attempts at PPS
                                            (to a closed port: a bare SYN each)
Rates stay far below the detector thresholds (UDP 200 pps, SYN 10 pps).
"""
import socket
import sys
import time

mode, dst, port, pps, secs = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5])
end = time.time() + secs
gap = 1.0 / pps
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if mode == "udp" else None
while time.time() < end:
    if udp is not None:
        try:
            udp.sendto(b"x" * 200, (dst, port))
        except OSError:
            pass
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            s.connect((dst, port))
        except (BlockingIOError, OSError):
            pass
        time.sleep(0.05)
        s.close()
    time.sleep(gap)
