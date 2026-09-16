"""
bng_subscriber_agent.py — persistent per-subscriber session + attack-
traffic control daemon, run on `suscriptor` (Broadband domain,
distributed VM lab). REPLACES simulation/bng_agent.py's BNGBlaster
wrapper -- see bngblaster_broadband_pipeline_status memory for why:
BNGBlaster's own sendto() succeeded but the frame was invisible to
every external observer on this lab, an unresolved bug. This project's
real BNG-side telemetry now comes from FreeRADIUS's own accounting
records on `bng` itself (telemetry/broadband_adapter.py tails those
over SSH) -- this daemon's only job is making real PPPoE-backed
subscriber sessions exist against accel-ppp and driving real hping3
attack traffic sourced from each subscriber's own PPP-assigned IP.

A "subscriber session" here is one macvlan sub-interface (roles/
suscriptor's setup_macvlans.sh.j2 creates macvlan1..N at boot, each
with its own MAC) running its own real `pppd` process (rp-pppoe
plugin) -- accel-ppp's pppoe module on `bng` sees each as a distinct
PPPoE peer (by Calling-Station-Id = MAC, plus a real PAP identity from
roles/suscriptor's pap-secrets), authenticates+accounts it via
FreeRADIUS, and negotiates back a real IPv4 address over IPCP. This
REPLACES an earlier IPoE/dhclient design (see roles/bng's own accel-
ppp.conf.j2 top-of-file comment): confirmed on a real run that IPoE
sessions authenticated and leased real DHCP IPs fine, but the kernel
ipoe.ko driver never actually redirected real subscriber DATA traffic
to the session's own interface, so FreeRADIUS accounting never
reflected any real attack traffic no matter how much flowed. PPPoE
sidesteps that entirely: each session's traffic is actively
encapsulated/decapsulated by the kernel's own generic PPP discipline
as it passes through the session's own real pppN interface, so that
interface's plain netdev counters are genuinely populated by the
traffic itself -- no separate classifier that has to choose to
redirect frames.

Killing a session's pppd process (SIGTERM) closes the PPP link
normally (LCP Term-Request), which is what makes accel-ppp/FreeRADIUS
emit a real Accounting-Stop record for that session -- a genuine
BNG-native session teardown, not a synthetic one.

Same tiny plain-text FIFO protocol as its predecessor (one command per
line): "baseline", "attack <scenario>", "stop", "stop_all" -- driven
over SSH by webtool/bng_ops.py's BngLifecycle in distributed mode
(_ssh_write_fifo), unchanged on that end.

Usage (on suscriptor, as root -- pppd/hping3/raw sockets need it):
  sudo python3 simulation/bng_subscriber_agent.py \\
      --target-ip 10.10.0.100 --parent-interface ens192 \\
      --fifo /run/bng-agent/cmd
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_DIR)
from simulation.bng_ipoe_config import SCENARIOS, BASELINE_SCENARIO, build_scenario  # noqa: E402

_MAX_SUBSCRIBERS = 8
_RUN_DIR = "/run/bng-subscribers"
_PPP_WAIT_S = 15
# Real per-session byte/packet counters come from FreeRADIUS's own
# accounting on `bng` (telemetry/broadband_adapter.py tails those) --
# but RADIUS accounting has no L4 visibility at all (it's a volumetric
# total, not a flow breakdown), same limitation BNGBlaster's own
# session-streams had (see simulation/bng_config.py's old module
# docstring: "the synthetic producer already knows what it's
# simulating"). This state file is that same convention's new home --
# broadband_adapter.py's distributed-mode collect() ALSO SSHes here to
# read which protocol/dst_port each currently-attacking subscriber's IP
# is meant to represent, merging it with FreeRADIUS's real rate data by
# IP.
_STATE_PATH = f"{_RUN_DIR}/active_scenario.json"


def _macvlan_iface(n: int) -> str:
    return f"macvlan{n}"


def _ppp_iface(n: int) -> str:
    return f"ppp-sub{n}"


def _username(n: int) -> str:
    """Must match roles/suscriptor's pap-secrets.j2 exactly."""
    return f"sub{n}"


def _log_path(n: int) -> str:
    return f"{_RUN_DIR}/pppd.sub{n}.log"


def _read_iface_ip(iface: str) -> str:
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", out)
    return m.group(1) if m else ""


class Subscriber:
    """One macvlan-backed subscriber session -- owns its real pppd
    process (a PPPoE session against accel-ppp on `bng`, over this
    macvlan) and (when attacking) its hping3 process."""

    def __init__(self, n: int):
        self.n = n
        self.macvlan_iface = _macvlan_iface(n)
        self.ppp_iface = _ppp_iface(n)
        self.ip = ""
        self._pppd_proc: subprocess.Popen = None
        self._attack_proc: subprocess.Popen = None

    def session_up(self) -> None:
        if self.ip:
            return  # already up
        os.makedirs(_RUN_DIR, exist_ok=True)
        argv = [
            "pppd",
            "plugin", "rp-pppoe.so", self.macvlan_iface,
            "user", _username(self.n),
            "linkname", f"sub{self.n}",
            "ifname", self.ppp_iface,
            "noipdefault",
            # nodefaultroute -- critical on a VM with 8 concurrent PPP
            # sessions: without it, EVERY session would try to overwrite
            # this VM's own default route (breaking SSH/ansible
            # reachability the moment the first session comes up).
            "nodefaultroute",
            # noauth -- confirmed on a real run: pppd's OWN default
            # (without this) is to REQUIRE THE PEER (accel-ppp) to
            # authenticate to US, not the other way around. accel-ppp
            # correctly rejects that request (an LCP ConfRej on OUR
            # <auth PAP> option -- a NAS has no reason to authenticate
            # itself to a subscriber), and pppd then reads that as "the
            # peer refused to authenticate" and tears the link straight
            # back down, in an infinite reconnect loop, without ever
            # reaching PAP negotiation for OUR OWN credentials (which
            # pap-secrets/`user` below handles independently of this
            # flag either way).
            "noauth",
            "persist", "maxfail", "0", "holdoff", "2",
            "-detach",
        ]
        with open(_log_path(self.n), "wb") as log_f:
            self._pppd_proc = subprocess.Popen(argv, stdout=log_f, stderr=subprocess.STDOUT)

        deadline = time.time() + _PPP_WAIT_S
        while time.time() < deadline:
            ip = _read_iface_ip(self.ppp_iface)
            if ip:
                self.ip = ip
                print(f"[SUBSCRIBER] {self.ppp_iface} (via {self.macvlan_iface}) got {ip}")
                return
            time.sleep(0.5)
        print(f"[SUBSCRIBER] {self.ppp_iface} did not come up within {_PPP_WAIT_S}s", file=sys.stderr)

    def session_down(self) -> None:
        self.stop_attack()
        if self._pppd_proc is None:
            return
        # SIGTERM -- closes the PPP link normally (LCP Term-Request),
        # the trigger for accel-ppp/FreeRADIUS to emit a real
        # Accounting-Stop record for this session (see this module's own
        # docstring). `persist` above only governs auto-reconnect after
        # an unexpected link drop, not signal handling -- SIGTERM still
        # terminates pppd outright.
        try:
            self._pppd_proc.terminate()
            self._pppd_proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            try:
                self._pppd_proc.kill()
            except OSError:
                pass
        self._pppd_proc = None
        self.ip = ""

    def start_attack(self, protocol: str, dst_port: int, rate_flags: list, target_ip: str) -> None:
        self.stop_attack()
        if not self.ip:
            print(f"[SUBSCRIBER] {self.ppp_iface} has no IP yet, cannot attack", file=sys.stderr)
            return
        argv = ["hping3", "-I", self.ppp_iface, "-a", self.ip]
        if protocol == "UDP":
            argv += ["--udp", "-p", str(dst_port), "--keep"]
        elif protocol == "TCP_SYN":
            argv += ["-S", "-p", str(dst_port), "--keep"]
        elif protocol == "ICMP":
            argv += ["--icmp"]
        argv += list(rate_flags)
        argv.append(target_ip)
        self._attack_proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop_attack(self) -> None:
        if self._attack_proc is None:
            return
        try:
            self._attack_proc.terminate()
            self._attack_proc.wait(timeout=3)
        except (subprocess.TimeoutExpired, OSError):
            try:
                self._attack_proc.kill()
            except OSError:
                pass
        self._attack_proc = None


class SubscriberPool:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.subscribers = {n: Subscriber(n) for n in range(1, _MAX_SUBSCRIBERS + 1)}
        self.current_scenario = None

    def _ensure_up(self, count: int) -> None:
        for n in range(1, count + 1):
            self.subscribers[n].session_up()

    def _ensure_down(self, keep: int) -> None:
        for n in range(keep + 1, _MAX_SUBSCRIBERS + 1):
            self.subscribers[n].session_down()

    def launch(self, scenario: str) -> None:
        scn = build_scenario(scenario)
        count = scn["subscriber_count"]
        self._ensure_up(count)
        self._ensure_down(count)
        for n in range(1, count + 1):
            self.subscribers[n].start_attack(scn["protocol"], scn["dst_port"], scn["rate_flags"], self.target_ip)
        self.current_scenario = scenario
        self._write_state(scn["protocol"], scn["dst_port"], count)
        print(f"[SUBSCRIBER] scenario={scenario} subscribers={count} started")

    def stop_attack_only(self) -> None:
        for sub in self.subscribers.values():
            sub.stop_attack()
        self._write_state(None, None, 0)

    def stop_all(self) -> None:
        for sub in self.subscribers.values():
            sub.session_down()
        self.current_scenario = None
        self._write_state(None, None, 0)

    def _write_state(self, protocol: str, dst_port: int, count: int) -> None:
        """src_ip -> {protocol, dst_port} for every subscriber currently
        attacking, keyed by their REAL PPP-assigned IP -- see this
        module's own top-of-file comment on why broadband_adapter.py
        needs this alongside FreeRADIUS's real rate data."""
        state = {}
        if protocol is not None:
            for n in range(1, count + 1):
                ip = self.subscribers[n].ip
                if ip:
                    state[ip] = {"protocol": protocol, "dst_port": dst_port}
        try:
            with open(_STATE_PATH, "w") as f:
                json.dump(state, f)
        except OSError as exc:
            print(f"[SUBSCRIBER] cannot write {_STATE_PATH}: {exc}", file=sys.stderr)


def _handle_line(pool: SubscriberPool, line: str) -> None:
    parts = line.strip().split(None, 1)
    if not parts:
        return
    cmd = parts[0]
    try:
        if cmd == "baseline":
            pool.launch(BASELINE_SCENARIO)
        elif cmd == "attack" and len(parts) == 2 and parts[1] in SCENARIOS:
            pool.launch(parts[1])
        elif cmd == "stop":
            # Falls back to the standing baseline, same posture as every
            # other domain in this project -- broadband's benign traffic
            # must never simply vanish.
            if pool.current_scenario == BASELINE_SCENARIO:
                pool.stop_attack_only()
                pool.launch(BASELINE_SCENARIO)
            else:
                pool.launch(BASELINE_SCENARIO)
        elif cmd == "stop_all":
            pool.stop_all()
        else:
            print(f"[SUBSCRIBER] unknown command: {line!r}", file=sys.stderr)
    except (OSError, ValueError) as exc:
        print(f"[SUBSCRIBER] command {line!r} failed: {exc}", file=sys.stderr)


def run(fifo_path: str, target_ip: str, start_baseline: bool) -> None:
    os.makedirs(os.path.dirname(fifo_path), exist_ok=True)
    if not os.path.exists(fifo_path):
        os.mkfifo(fifo_path, 0o666)

    pool = SubscriberPool(target_ip=target_ip)
    if start_baseline:
        pool.launch(BASELINE_SCENARIO)

    while True:
        with open(fifo_path, "r") as f:
            for line in f:
                if line.strip():
                    _handle_line(pool, line)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target-ip", required=True)
    p.add_argument("--parent-interface", required=True, help="informational only -- macvlans are created by roles/suscriptor's setup_macvlans.sh.j2, not by this script")
    p.add_argument("--fifo", default="/run/bng-agent/cmd")
    p.add_argument("--no-baseline", action="store_true")
    args = p.parse_args()

    if sys.platform != "linux":
        print("ERROR: needs Linux (raw sockets, pppd) -- run this on suscriptor, not here.", file=sys.stderr)
        sys.exit(1)

    run(fifo_path=args.fifo, target_ip=args.target_ip, start_baseline=not args.no_baseline)


if __name__ == "__main__":
    main()
