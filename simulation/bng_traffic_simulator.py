"""
bng_traffic_simulator.py — Fixed Broadband Domain (BNG) DDoS simulator.

Linux-only -- BNGBlaster needs raw-socket access (root or
cap_net_raw,cap_net_admin) and real network interfaces (a veth pair is
the simplest setup -- see simulation/bng_setup_netns.sh). It does not
run on macOS, so this is written and reviewed here but only actually
exercised on the Ubuntu test VM (same split as the rest of this repo's
O-RAN pipeline -- see oran_e2_pipeline_status memory).

Unlike simulation/ul_traffic_simulator.py (a pure-Python synthetic
producer standing in for telemetry no real pipeline could deliver),
this drives the REAL bngblaster binary: real PPPoE/IPoE sessions, real
packets on the wire, real counters read back over its control socket
(simulation/bng_socket.py). BNGBlaster has no push/streaming telemetry
(no gRPC dial-out, no Kafka/Prometheus plugin) -- only a Unix-socket
JSON-RPC API, so this polls it on a tick loop.

Telemetry is collected PER SESSION (session-info for each session's own
framed IP, session-streams for its own tx rate) -- BNGBlaster's native
unit of "one subscriber" -- not pre-aggregated across sessions. This
matters for two of the five attack types: Distributed TCP SYN Flood and
Low and Slow are only classifiable as such if DDoSDetectionEngine sees
DISTINCT source IPs per session (its entropy/source-count checks operate
on TelemetryEvent.src_ip) -- collapsing all sessions into one row would
make every scenario look like a single attacker.

Output: appends rows to DEFAULT_CSV_PATH in the column order
BroadbandAdapter.collect() expects (telemetry/broadband_adapter.py) --
same role parse_xapp_kpm_log.py's CSV plays for MobileNetworkAdapter.

Usage (on the Ubuntu VM, as root or with cap_net_raw/cap_net_admin set
on the bngblaster binary -- see simulation/bng_install.sh):
  sudo python3 simulation/bng_traffic_simulator.py --scenario syn_flood
  sudo python3 simulation/bng_traffic_simulator.py --scenario udp_flood
  sudo python3 simulation/bng_traffic_simulator.py --scenario icmp_flood
  sudo python3 simulation/bng_traffic_simulator.py --scenario distributed_syn_flood
  sudo python3 simulation/bng_traffic_simulator.py --scenario low_and_slow --duration 120
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))
from simulation.bng_config import SCENARIOS, build_scenario  # noqa: E402
from simulation.bng_socket import BngControlSocket, wait_for_socket  # noqa: E402

DEFAULT_CSV_PATH = "/tmp/ddos_bng_events.csv"
# Must match telemetry/broadband_adapter.py's _CSV_COLUMNS exactly.
_CSV_COLUMNS = [
    "timestamp", "session_id", "device_id", "src_ip", "dst_ip", "dst_port",
    "protocol", "pps", "bps", "sessions_established", "sessions_flapped",
]

DEFAULT_CONFIG_PATH = "/tmp/bng_run_config.json"
DEFAULT_SOCK_PATH = "/tmp/bng_run.sock"
_NORMAL_DST_PORT = 80
_NORMAL_PROTOCOL = "TCP"


def _extract_rate(stats: dict) -> tuple:
    """
    Pulls (pps, bps) out of a real `session-streams` response, confirmed
    against a live run:
        {"status": "ok", "code": 200, "session-streams": {
            "session-id": 1, "rx-packets": 0, "tx-packets": 6,
            "rx-pps": 0, "tx-pps": 0, "rx-bps-l2": 0, "tx-bps-l2": 728,
            "rx-mbps-l2": 0.0, "tx-mbps-l2": 0.000728, "streams": []}}
    -- "session-streams" is the per-SESSION aggregate (not a list), with
    an optional nested "streams" list breaking it down per individual
    stream (empty unless BNGBlaster attaches per-stream detail; this
    pipeline doesn't need that breakdown, the session-level tx-pps/
    tx-bps-l2 already covers what one subscriber session sent). Field
    name is "...-bps-l2" (the actual key), not the "...-bps" this code
    originally guessed -- that earlier guess silently produced bps=0.0
    forever (no error, just an always-empty bps column) until a real
    run surfaced the right name.
    """
    node = stats.get("session-streams", stats)
    if not isinstance(node, dict):
        return 0.0, 0.0
    pps = node.get("tx-pps", node.get("rx-pps", 0.0))
    bps = node.get("tx-bps-l2", node.get("rx-bps-l2", 0.0))
    return float(pps or 0.0), float(bps or 0.0)


def _extract_session_address(info: dict, session_id: int) -> tuple:
    """Pulls this session's own framed (subscriber-side) IPv4 address out
    of a session-info response -- the real per-subscriber source address
    that makes distinct-source detection (Distributed TCP SYN Flood,
    Low and Slow) possible. Returns (address, confirmed) -- confirmed is
    True only when a real address field was found, so the caller knows
    not to cache a placeholder permanently.

    Response is wrapped (confirmed on a real run: {"status":...,
    "session-info": {"session-id":..., ...}}), unlike the flat dict
    this originally assumed -- that bug made every session fall through
    to the placeholder AND, since it read "session-id" from the same
    (wrong, top-level) dict, always defaulted to 0, producing the exact
    same placeholder IP for every single session regardless of its real
    session-id. session_id is now taken from the caller's own loop
    variable instead of re-reading it back out of the response.

    A real run's session-info had no IP address field at all yet (DHCP
    was still stuck pending) -- this fallback is what made that failure
    visible at all (every session reporting the literal same src_ip)
    instead of silently collapsing into one false single-attacker
    signature.
    """
    node = info.get("session-info", info)
    if isinstance(node, dict):
        for key in ("ipv4-address", "framed-ip-address", "ip-address"):
            addr = node.get(key)
            if isinstance(addr, str) and addr:
                return addr.split("/")[0], True
    placeholder = f"10.50.{(session_id // 254) % 254}.{(session_id % 254) + 1}"
    return placeholder, False


def _extract_session_counters(stats: dict) -> tuple:
    sc = stats.get("session-counters", stats)
    established = sc.get("sessions-established", sc.get("sessions", 0))
    flapped = sc.get("sessions-flapped", 0)
    return int(established or 0), int(flapped or 0)


def _append_csv_rows(csv_path: str, rows: list) -> None:
    if not rows:
        return
    is_new = not os.path.exists(csv_path)
    with open(csv_path, "a", newline="") as f:
        if is_new:
            f.write(",".join(_CSV_COLUMNS) + "\n")
        for row in rows:
            f.write(",".join(str(row[c]) for c in _CSV_COLUMNS) + "\n")


def run(
    scenario: str,
    target_ip: str,
    bng_host: str,
    duration_s: int,
    tick_s: float,
    attack_start_s: int,
    attack_end_s: int,
    csv_path: str,
    bng_binary: str,
    access_interface: str,
    network_interface: str,
    config_path: str,
    sock_path: str,
) -> None:
    scn = build_scenario(
        scenario=scenario,
        target_ip=target_ip,
        access_interface=access_interface,
        network_interface=network_interface,
    )
    Path(config_path).write_text(json.dumps(scn["config"], indent=2))

    if os.path.exists(sock_path):
        os.remove(sock_path)

    print(f"[BNG] launching {bng_binary} -C {config_path} -S {sock_path} "
          f"(scenario={scenario}, sessions={scn['sessions']})")
    proc = subprocess.Popen([bng_binary, "-C", config_path, "-S", sock_path])
    try:
        wait_for_socket(sock_path, timeout_s=10.0)
        ctrl = BngControlSocket(sock_path)

        attack_started = scn["autostart"]
        attack_stopped = attack_started and scenario == "low_and_slow"
        # session-id is assumed sequential starting at 1, matching every
        # other BNGBlaster doc example -- see bng_socket.py's docstring.
        session_ids = list(range(1, scn["sessions"] + 1))
        session_ips = {}
        session_confirmed = set()

        elapsed = 0.0
        while elapsed < duration_s:
            # stream-start/stream-stop filter by "name" (or session-id/
            # flow-id) -- NOT "stream-group-id" (confirmed on a real run:
            # that argument got a clean {"status":"error","message":
            # "invalid argument"} every time, silently, since BngControlSocket
            # didn't used to raise on an error status -- see its docstring).
            # icmp-client-start/-stop still use the unverified
            # icmp-client-group-id (no real run has exercised the icmp_flood
            # scenario yet).
            if not attack_started and elapsed >= attack_start_s:
                print(f"[BNG] starting attack ({scn['attack_kind']} {scn['attack_name'] or scn['attack_group_id']}, {scenario})")
                cmd = "stream-start" if scn["attack_kind"] == "stream" else "icmp-client-start"
                args = {"name": scn["attack_name"]} if scn["attack_kind"] == "stream" else {"icmp-client-group-id": scn["attack_group_id"]}
                try:
                    ctrl.call(cmd, args)
                except (OSError, RuntimeError, json.JSONDecodeError) as exc:
                    print(f"[BNG] {cmd} failed: {exc}", file=sys.stderr)
                attack_started = True

            if attack_started and not attack_stopped and elapsed >= attack_end_s:
                print(f"[BNG] stopping attack ({scn['attack_kind']} {scn['attack_name'] or scn['attack_group_id']})")
                cmd = "stream-stop" if scn["attack_kind"] == "stream" else "icmp-client-stop"
                args = {"name": scn["attack_name"]} if scn["attack_kind"] == "stream" else {"icmp-client-group-id": scn["attack_group_id"]}
                try:
                    ctrl.call(cmd, args)
                except (OSError, RuntimeError, json.JSONDecodeError) as exc:
                    print(f"[BNG] {cmd} failed: {exc}", file=sys.stderr)
                attack_stopped = True

            now = time.time()
            rows = []

            try:
                counters = ctrl.call("session-counters")
            except (OSError, RuntimeError, json.JSONDecodeError) as exc:
                print(f"[BNG] session-counters failed: {exc}", file=sys.stderr)
                counters = {}
            established, flapped = _extract_session_counters(counters)

            for sid in session_ids:
                # Re-fetched every tick until a REAL address shows up
                # (i.e. not yet "confirmed") -- caching the very first
                # lookup unconditionally meant a session still stuck in
                # DHCP at that point got its placeholder IP locked in
                # forever, never updated once DHCP actually completed a
                # tick or two later.
                if sid not in session_confirmed:
                    try:
                        info = ctrl.call("session-info", {"session-id": sid})
                        addr, confirmed = _extract_session_address(info, sid)
                        session_ips[sid] = addr
                        if confirmed:
                            session_confirmed.add(sid)
                    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
                        print(f"[BNG] session-info({sid}) failed: {exc}", file=sys.stderr)
                        continue
                src_ip = session_ips.get(sid)
                if not src_ip:
                    continue

                try:
                    stats = ctrl.call("session-streams", {"session-id": sid})
                except (OSError, RuntimeError, json.JSONDecodeError) as exc:
                    print(f"[BNG] session-streams({sid}) failed: {exc}", file=sys.stderr)
                    continue
                pps, bps = _extract_rate(stats)
                if pps <= 0.0 and bps <= 0.0:
                    continue

                is_attack_session = attack_started and not attack_stopped
                rows.append({
                    "timestamp": f"{now:.6f}",
                    "session_id": sid,
                    "device_id": bng_host,
                    "src_ip": src_ip,
                    "dst_ip": target_ip,
                    "dst_port": scn["dst_port"] if is_attack_session else _NORMAL_DST_PORT,
                    "protocol": scn["protocol"] if is_attack_session else _NORMAL_PROTOCOL,
                    "pps": f"{pps:.3f}",
                    "bps": f"{bps:.3f}",
                    "sessions_established": established,
                    "sessions_flapped": flapped,
                })

            _append_csv_rows(csv_path, rows)
            time.sleep(tick_s)
            elapsed += tick_s
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scenario", choices=SCENARIOS, default="syn_flood")
    p.add_argument("--target-ip", default="10.0.2.10")
    p.add_argument("--bng-host", default="bng-blaster-1")
    p.add_argument("--duration", type=int, default=60, help="total run length, seconds")
    p.add_argument("--tick", type=float, default=1.0, help="poll interval, seconds")
    p.add_argument("--attack-start", type=int, default=10, help="seconds into the run")
    p.add_argument("--attack-end", type=int, default=40, help="seconds into the run")
    p.add_argument("--csv-path", default=DEFAULT_CSV_PATH)
    p.add_argument("--bng-binary", default="/usr/sbin/bngblaster")
    p.add_argument("--access-interface", default="veth-a")
    p.add_argument("--network-interface", default="veth-n")
    p.add_argument("--config-path", default=DEFAULT_CONFIG_PATH)
    p.add_argument("--sock-path", default=DEFAULT_SOCK_PATH)
    args = p.parse_args()

    if sys.platform != "linux":
        print("ERROR: bngblaster requires Linux (raw sockets) -- run this on the Ubuntu test VM, not here.",
              file=sys.stderr)
        sys.exit(1)

    run(
        scenario=args.scenario,
        target_ip=args.target_ip,
        bng_host=args.bng_host,
        duration_s=args.duration,
        tick_s=args.tick,
        attack_start_s=args.attack_start,
        attack_end_s=args.attack_end,
        csv_path=args.csv_path,
        bng_binary=args.bng_binary,
        access_interface=args.access_interface,
        network_interface=args.network_interface,
        config_path=args.config_path,
        sock_path=args.sock_path,
    )


if __name__ == "__main__":
    main()
