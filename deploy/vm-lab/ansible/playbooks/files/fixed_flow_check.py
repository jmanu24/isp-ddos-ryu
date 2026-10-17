"""Checks bng_flow_api's /telemetry payload for one probe.

stdin: the payload JSON (plain or base64). Args:
  --ip SUBSCRIBER_IP --mac MAC --dst DST --port PORT --udp-min PPS --syn-min PPS
Exit 0 and print one summary line when BOTH the UDP flow row and the TCP_SYN
row exist for that subscriber with the expected destination/port, the right
subscriber MAC and an accel-ppp session id; else exit 1 with what is missing.
"""
import argparse
import base64
import json
import sys

ap = argparse.ArgumentParser()
ap.add_argument("--ip"); ap.add_argument("--mac"); ap.add_argument("--dst")
ap.add_argument("--udp-port", type=int); ap.add_argument("--syn-port", type=int)
ap.add_argument("--udp-min", type=float, default=5.0); ap.add_argument("--syn-min", type=float, default=1.0)
ap.add_argument("--passive", action="store_true",
                help="no probe: every subscriber must show baseline flows with its identity")
ap.add_argument("--count", type=int, default=10); ap.add_argument("--prefix", default="10.20.0"); ap.add_argument("--offset", type=int, default=200)
ap.add_argument("--min-pps", type=float, default=0.3)
a = ap.parse_args()

raw = sys.stdin.read().strip()
if not raw.startswith("{"):
    raw = base64.b64decode(raw).decode()
payload = json.loads(raw)


def passive():
    """Each subscriber n: some flow row with pps >= min-pps toward dst, carrying
    MAC 02:00:00:00:00:<n> and a session id."""
    bad, seen = [], 0
    for n in range(1, a.count + 1):
        ip, mac = "%s.%d" % (a.prefix, a.offset + n), "02:00:00:00:00:%02x" % n
        rows = [r for r in payload.get("flows", []) if r["src_ip"] == ip and r["dst_ip"] == a.dst and r["pps"] >= a.min_pps]
        if not rows:
            bad.append("%s: no flow toward %s" % (ip, a.dst))
        elif not all((r.get("mac") or "").lower() == mac and r.get("session_id") for r in rows):
            bad.append("%s: row without mac %s / session id" % (ip, mac))
        else:
            seen += 1
    if bad:
        print("; ".join(bad)); sys.exit(1)
    protos = sorted({r["protocol"] for r in payload["flows"] if r["dst_ip"] == a.dst})
    print("%d/%d subscribers show baseline flows toward %s with MAC + session id (protocols: %s)" % (seen, a.count, a.dst, ", ".join(protos)))
    sys.exit(0)


if a.passive:
    passive()


def find(proto, port, minimum):
    for r in payload.get("flows", []):
        if (r["src_ip"], r["dst_ip"], r["protocol"], r["dst_port"]) == (a.ip, a.dst, proto, port) and r["pps"] >= minimum:
            return r
    return None


problems = []
udp, syn = find("UDP", a.udp_port, a.udp_min), find("TCP_SYN", a.syn_port, a.syn_min)
if not udp:
    problems.append("no UDP row for %s -> %s:%s with pps >= %s" % (a.ip, a.dst, a.udp_port, a.udp_min))
if not syn:
    problems.append("no TCP_SYN row for %s -> %s:%s with pps >= %s" % (a.ip, a.dst, a.syn_port, a.syn_min))
for name, row in (("UDP", udp), ("TCP_SYN", syn)):
    if row:
        if (row.get("mac") or "").lower() != a.mac.lower():
            problems.append("%s row has mac %r, expected %s" % (name, row.get("mac"), a.mac))
        if not row.get("session_id"):
            problems.append("%s row has no accel-ppp session id" % name)
if problems:
    print("; ".join(problems))
    sys.exit(1)
print("UDP %.1f pps, TCP_SYN %.1f pps, mac %s, session %s" % (udp["pps"], syn["pps"], udp["mac"], udp["session_id"]))
