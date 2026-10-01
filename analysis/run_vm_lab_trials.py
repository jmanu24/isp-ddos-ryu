#!/usr/bin/env python3
"""Run isolated, repeated DDoS trials in the distributed VM lab.

The runner is intentionally conservative: one trial is allowed to finish,
recover and cool down before the next one starts.  Individual trials use one
attacker.  MULTIDOMAIN_FLOOD uses one attacker *per domain* because a
multidomain event cannot exist with a single global source.

Outputs:
  trials_long.csv  one row per domain/vector/run, including timestamps/status
  trials_table.csv the wide Td/Tm/Tr table used by the thesis
  trials.jsonl     append-only checkpoint suitable for --resume
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import random
import re
import shlex
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Tuple


DOMAINS = ("enterprise", "broadband", "mobile", "peering")
VECTORS = ("TCP_SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "MULTIDOMAIN_FLOOD")
TARGET_IP = "10.55.0.100"

# 2nd review pass, finding 2: observed_pps sums tx_packets across EVERY
# non-loopback interface on the host (Lab.sample_tx_packets()'s own
# docstring already says so) -- that includes this very SSH/ansible
# management traffic, not just the attack. A generator that silently
# never launched (missing binary, bad args, permission error) could
# still leave a small nonzero reading from incidental management
# chatter alone and get wrongly accepted as a confirmed NO_DETECTION.
# Not a precise calibration -- just comfortably above what a handful of
# SSH round trips over an attack_duration-sized window produce, and
# comfortably below any actually-running flood (hping3's own -i u1000
# alone is already ~1000 pps nominal).
MIN_CONFIRMED_ATTACK_PPS = 20.0

# Campaign mode -- decided and validated ONCE, before the statistical
# campaign starts (main(), via resolve_effective_vectors() below), not
# discovered mid-run. Before this, "isolated" vs. "multidomain" was only
# an implicit side effect of whichever vectors happened to be passed in
# --vectors (MULTIDOMAIN_FLOOD mixed in as just another vector value) --
# a run with 1 domain and MULTIDOMAIN_FLOOD in --vectors would silently
# print "Skipping MULTIDOMAIN_FLOOD" per iteration instead of failing
# fast at startup.
#   isolated     -- one domain per trial (TCP/UDP/ICMP_FLOOD only)
#   multidomain  -- MULTIDOMAIN_FLOOD only, one real attacker per domain,
#                   all domains firing concurrently (needs >=2 --domains)
#   both         -- every vector in --vectors, mixed (previous behavior,
#                   still the default so existing invocations don't change)
TRIAL_MODES = ("isolated", "multidomain", "both")

# Mobile's one representative attacker is ue1 (netns on host `ue`,
# cu1=`ran` -> du1=`du` -> ue1 -- see mobile-bringup-order memory). The
# other 4 UEs are left out of the trial design the same way broadband
# only uses `suscriptor` (a single host managing several subscriber
# sources) and peering only uses `peer-router`: one real attacker per
# domain is the point for the ISOLATED vectors, not exhaustive coverage.
HOST_BY_DOMAIN = {
    "enterprise": "ent-site-1",
    "broadband": "suscriptor",
    "mobile": "ue",
    "peering": "peer-router",
}

# Item 7 fix: MULTIDOMAIN_FLOOD launching exactly one attacker per
# selected domain can NEVER cross settings.DIST_MIN_SOURCES (5) -- there
# are only 4 domains total, so even selecting all of them gives 4
# sources, always short of the 5 MULTIDOMAIN_DISTRIBUTED_ATTACK itself
# requires (detection/engine.py). That means this scenario could never
# actually demonstrate the hypothesis it exists to test, regardless of
# which/how many --domains were picked -- it could still trigger OTHER
# detections, but not the one named after it. All 5 ent-site-N hosts are
# real, independent attack sources already used for exactly this reason
# by the enterprise domain's own isolated DDoS scenario (see roles/
# enterprise_site's own comment: "needed to cross DIST_MIN_SOURCES=5")
# -- reusing all 5 here, ONLY for MULTIDOMAIN_FLOOD (isolated vectors
# still use just ent-site-1, unchanged), lets enterprise alone satisfy
# DIST_MIN_SOURCES whenever it's one of the selected domains, instead of
# depending on how many OTHER domains happened to be picked too.
ENTERPRISE_MULTIDOMAIN_HOSTS = (
    "ent-site-1", "ent-site-2", "ent-site-3", "ent-site-4", "ent-site-5",
)

SOURCE_HINT = {
    "enterprise": "10.70.0.11",
    "mobile": "10.45.1.2",
    "peering": "10.30.0.2",
}

# Minimal kernel-socket SYN/UDP flood for the mobile domain's UE netns --
# same approach as simulation/bng_flood.py (hping3's raw-socket path
# needs real Ethernet L2 framing; tun_srsue is POINTOPOINT/NOARP, so it
# never sees a single packet, exactly like broadband's own macvlan/PPP
# interfaces before that script replaced hping3 there too). Pushed to
# the UE host as a plain file (not run via `python3 -c`) to avoid
# quoting a multi-line script through two layers of shell (this
# process's own command string -> ansible's shell module -> the
# remote /bin/sh).
_MOBILE_FLOOD_SCRIPT = '''#!/usr/bin/env python3
import socket
import sys


def tcp_syn_flood(dst_ip, dst_port):
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setblocking(False)
            s.connect_ex((dst_ip, dst_port))
        except OSError:
            pass
        finally:
            s.close()


def udp_flood(dst_ip, dst_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"\\x00" * 32
    while True:
        try:
            s.sendto(payload, (dst_ip, dst_port))
        except OSError:
            pass


if __name__ == "__main__":
    proto, dst_ip, dst_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    if proto == "udp":
        udp_flood(dst_ip, dst_port)
    else:
        tcp_syn_flood(dst_ip, dst_port)
'''

DETECTION_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?).*"
    r"FlowStatsIDS \[(?P<domain>[^]]+)] DETECTION: ATTACK_DETECTED "
    r"(?P<kind>\S+) source=(?P<src>\S+) destination=(?P<dst>[^:]+):"
)
MITIGATION_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?).*"
    r"FlowStatsIDS \[(?P<domain>[^]]+)] MITIGATION: "
    r"(?P<action>BLOCK|THROTTLE|BGP_FLOWSPEC_DISCARD)\s+\S+.*"
    r"(?:source|src_ip)=(?P<src>\S+)"
)
RECOVERY_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?).*"
    r"FlowStatsIDS \[(?P<domain>[^]]+)] MITIGATION: "
    r"(?P<action>UNBLOCK|UNTHROTTLE)\s+\S+.*(?:source|src_ip)=(?P<src>\S+)"
)


@dataclass
class TrialResult:
    run_id: str
    iteration: int
    domain: str
    vector: str
    source: str
    target: str
    attack_at: str = ""
    detection_at: str = ""
    mitigation_at: str = ""
    recovery_at: str = ""
    Td_s: Optional[float] = None
    Tm_s: Optional[float] = None
    Tr_s: Optional[float] = None
    status: str = "ERROR"
    error: str = ""
    # Traceability (item 6): everything needed to tell two rows apart
    # besides domain/vector/iteration, and to tell a real detection event
    # apart from a mere log timestamp (item 5) -- see each field's own
    # Lab method/constant for how it's actually measured.
    code_version: str = ""        # git commit hash, from Lab.code_version()
    detection_mode: str = ""      # "isolated" | "multidomain" -- see Lab.set_detection_mode()
    scenario_mode: str = ""       # the campaign's --mode (isolated|multidomain|both)
    observed_pps: Optional[float] = None  # measured over the attack window -- see Lab.sample_tx_packets()
    traffic_recovered: Optional[bool] = None  # legitimate-traffic probe AFTER Tr_s -- see check_traffic_recovery()
    generator_confirmed: Optional[bool] = None  # independent evidence the generator ran -- see Lab.generator_confirmed()
    mitigation_withdrawn: Optional[bool] = None  # the block/throttle rule itself is gone -- see Lab.mitigation_withdrawn()


class LabError(RuntimeError):
    pass


class Lab:
    def __init__(self, repo: Path, inventory: Path, dry_run: bool = False):
        self.repo = repo
        self.inventory = inventory
        self.dry_run = dry_run
        self.detection_mode = "multidomain"  # updated by set_detection_mode()
        self._code_version: Optional[str] = None

    def _run(self, argv: list[str], timeout: int = 45, check: bool = True) -> str:
        print("+", " ".join(argv), flush=True)
        if self.dry_run:
            return ""
        cp = subprocess.run(
            argv, cwd=self.repo, text=True, capture_output=True, timeout=timeout
        )
        combined = "\n".join(part for part in (cp.stdout, cp.stderr) if part)
        if argv and argv[0] == "ansible" and (
            "No hosts matched" in combined
            or "Could not match supplied host pattern" in combined
            or "No inventory was parsed" in combined
        ):
            raise LabError(f"Ansible did not execute the requested host:\n{combined.strip()}")
        if check and cp.returncode != 0:
            raise LabError(f"command failed ({cp.returncode}): {cp.stderr.strip()}\n{cp.stdout.strip()}")
        return cp.stdout

    def shell(self, host: str, command: str, *, background: bool = False,
              timeout: int = 45, check: bool = True) -> str:
        argv = [
            "ansible", host, "-i", str(self.inventory), "-b",
        ]
        if background:
            argv += ["-B", "180", "-P", "0"]
        argv += ["-m", "shell", "-a", command]
        return self._run(argv, timeout=timeout, check=check)

    def playbook(self, path: str, *, limit: str, skip_tags: str = "",
                 tags: str = "", extra_vars: Optional[dict] = None,
                 timeout: int = 300) -> str:
        # --become unconditionally: this process runs ansible-playbook
        # from the repo root with an explicit -i, so deploy/vm-lab/
        # ansible/ansible.cfg's own `become = True` default (which only
        # loads when the CWD is that directory, or ANSIBLE_CONFIG points
        # at it) is never picked up here -- several of this playbook's
        # own tasks are commented "become=true inherited" assuming
        # exactly that default. Forcing it here matches what they expect
        # regardless of CWD.
        argv = ["ansible-playbook", "-i", str(self.inventory), path,
                "--limit", limit, "--become"]
        if skip_tags:
            argv += ["--skip-tags", skip_tags]
        if tags:
            argv += ["--tags", tags]
        for key, value in (extra_vars or {}).items():
            argv += ["-e", f"{key}={value}"]
        return self._run(argv, timeout=timeout)

    def code_version(self) -> str:
        """"<runner commit>+controller=<deployed commit>", recorded on
        every TrialResult (item 6: traceability). Minor fix: this used to
        report ONLY the runner process's own local checkout -- but the
        actual detection/decision/mitigation code under test runs on
        `orchestrator` (/opt/Tesis_Controller), a SEPARATE checkout this
        script does not control or even necessarily share a filesystem
        with. The two can legitimately differ (this analysis/ script and
        the controller's own git pull happen independently), so a trial
        run from an up-to-date runner against a stale orchestrator
        checkout would otherwise silently claim the wrong code version.
        `git describe`/a full status diff isn't used for either side (a
        dirty worktree during an active campaign is normal, not worth
        failing over), just each side's own commit + a dirty marker."""
        if self._code_version is not None:
            return self._code_version
        self._code_version = f"{self._git_version(self.repo)}+controller={self._deployed_controller_version()}"
        return self._code_version

    @staticmethod
    def _git_version(path) -> str:
        try:
            commit = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"], cwd=path,
                text=True, capture_output=True, timeout=10, check=True,
            ).stdout.strip()
            dirty = subprocess.run(
                ["git", "status", "--porcelain"], cwd=path,
                text=True, capture_output=True, timeout=10, check=True,
            ).stdout.strip()
            return commit + ("-dirty" if dirty else "")
        except Exception:  # noqa: BLE001 -- never block a trial over this
            return "unknown"

    def _deployed_controller_version(self) -> str:
        if self.dry_run:
            return "dry-run"
        try:
            out = self.shell(
                "orchestrator",
                "cd /opt/Tesis_Controller && git rev-parse --short HEAD && "
                "git status --porcelain",
                timeout=15,
            )
        except (LabError, subprocess.TimeoutExpired):
            return "unknown"
        # Minor fix (2nd review pass): ansible's own ad-hoc output
        # prepends a "<host> | CHANGED | rc=0 >>" header line before the
        # command's real stdout -- the same shape log_size()/
        # attack_start() already work around with a regex instead of a
        # naive first-line read. A plain `out.splitlines()[0]` here would
        # capture THAT header instead of the git hash it looks like it's
        # reading, every single time.
        m = re.search(r"(?m)^([0-9a-f]{7,40})\s*$", out)
        if not m:
            return "unknown"
        commit = m.group(1)
        # Any non-blank line after the matched commit line is `git status
        # --porcelain`'s own dirty-file output.
        dirty = bool(re.search(r"(?m)^\s*\S", out[m.end():]))
        return commit + ("-dirty" if dirty else "")

    def set_detection_mode(self, mode: str) -> None:
        """Switches "isolated" vs. "multidomain" detection (item 1) by
        overriding ryu-manager's DETECTION_CROSS_DOMAIN_CORRELATION via a
        TRANSIENT systemd drop-in (/run, not /etc -- gone on the next
        reboot/redeploy, which falls back to the ansible-managed unit's
        own default) and restarting it. A plain `systemctl set-
        environment` does NOT work here: the unit file already sets this
        same variable via its own Environment= line, which takes
        precedence over the manager-level default -- a drop-in's
        Environment= is the one mechanism that actually overrides it.
        Deliberately does NOT touch anything else -- the attack side
        (sources/rates/duration/target/thresholds) is completely
        untouched, so the same attack runs in both modes.

        ALWAYS applies and restarts -- the early `if self.detection_mode
        == mode: return` this used to have was wrong (item 1 bug): a
        fresh Lab instance always assumes "multidomain" (its __init__
        default), so a SECOND campaign process started with --detection-
        mode isolated right after a FIRST one already left the real
        controller in isolated mode would see self.detection_mode
        default to "multidomain", skip applying anything, and silently
        keep running (and labeling every TrialResult) against whatever
        mode the controller actually happened to be left in -- in-
        process state was never a reliable proxy for the real, separate
        controller process's actual state. Verified instead by reading
        the controller's own STARTUP/DETECTION_MODE log line emitted
        fresh after THIS restart (ryu_controller_2.py), not just
        `systemctl is-active` (active-but-still-the-old-mode would pass
        that check)."""
        if mode not in ("isolated", "multidomain"):
            raise LabError(f"invalid detection mode: {mode}")
        value = "false" if mode == "isolated" else "true"
        command = (
            "mkdir -p /run/systemd/system/ryu-manager.service.d && "
            f"printf '[Service]\\nEnvironment=DETECTION_CROSS_DOMAIN_CORRELATION={value}\\n' "
            "> /run/systemd/system/ryu-manager.service.d/99-detection-mode.conf && "
            "systemctl daemon-reload && systemctl restart ryu-manager"
        )
        print(f"Switching detection mode: {self.detection_mode} -> {mode} (always applied, never skipped)",
              flush=True)
        offset = 0 if self.dry_run else self.log_size()
        self.shell("orchestrator", command, timeout=60)
        if self.dry_run:
            self.detection_mode = mode
            return
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.healthy("orchestrator", "systemctl is-active ryu-manager"):
                log = self.log_from(offset)
                m = re.search(r"DETECTION_MODE=(\w+)", log)
                if m:
                    if m.group(1) != mode:
                        raise LabError(
                            f"ryu-manager restarted but reported DETECTION_MODE={m.group(1)}, "
                            f"expected {mode} -- the drop-in did not take effect as intended"
                        )
                    self.detection_mode = mode
                    return
            time.sleep(3)
        raise LabError(
            f"ryu-manager did not report DETECTION_MODE={mode} in its own startup log "
            "after switching and restarting -- its own log line is the source of truth here, "
            "not just the unit being active"
        )

    # Per-domain command to dump the attack SOURCE's own interface
    # counters, used by sample_tx_packets() below to measure the actually
    # ACHIEVED send rate over the attack window -- an approximation (host-
    # level counters, not a packet capture), not a precise per-flow rate,
    # and documented as such wherever it's reported (item 6: "tasas
    # observadas", item 5: don't overclaim precision logs can't back up).
    _RATE_PROBE_CMD = {
        "enterprise": "cat /proc/net/dev",
        "peering": "cat /proc/net/dev",
        "broadband": "cat /proc/net/dev",
        "mobile": "ip netns exec ue1 cat /proc/net/dev",
    }

    def sample_tx_packets(self, domain: str, vector: str = "") -> Optional[int]:
        """Sum of tx_packets across every non-loopback interface on the
        domain's attack source(s) (its own netns for mobile; all 5
        ent-site-N hosts for enterprise's own MULTIDOMAIN_FLOOD, matching
        launch()'s own multi-host fan-out -- item 7 fix). Two calls
        bracketing the attack window, divided by elapsed wall time, give
        an observed pps -- see run_trial()'s own use of this."""
        cmd = self._RATE_PROBE_CMD.get(domain)
        if cmd is None or self.dry_run:
            return None
        hosts = (ENTERPRISE_MULTIDOMAIN_HOSTS if domain == "enterprise" and vector == "MULTIDOMAIN_FLOOD"
                 else (HOST_BY_DOMAIN[domain],))
        total = 0
        for host in hosts:
            res = self.shell(host, cmd, timeout=10, check=False)
            for line in res.splitlines():
                if ":" not in line:
                    continue
                iface, rest = line.split(":", 1)
                if iface.strip() == "lo":
                    continue
                fields = rest.split()
                if len(fields) < 10:
                    continue
                try:
                    total += int(fields[9])  # tx_packets, see /proc/net/dev's own column order
                except ValueError:
                    continue
        return total

    # Known failure signatures to look for in a generator's own per-run
    # log (2nd review pass, finding 2) -- hping3's default (non -V) mode
    # prints NOTHING to stdout/stderr on a clean run (an EMPTY log is the
    # expected happy path, not a red flag), so "file is non-empty" would
    # be the wrong signal; these markers catch the actual failure modes
    # instead (binary missing, bad args/permissions, or -- for the
    # mobile flood's own python3 script -- an uncaught exception at
    # startup, which prints a traceback before the loop even begins).
    _GENERATOR_ERROR_MARKERS = (
        "command not found",
        "No such file or directory",
        "Permission denied",
        "Operation not permitted",
        "Traceback (most recent call last)",
        "No such device",
    )

    def generator_confirmed(self, domain: str, run_id: str, vector: str = "") -> Optional[bool]:
        """Independent confirmation that the attack generator itself
        actually ran, from its OWN per-run log
        (/tmp/ddos-trial-{run_id}.log, written by both _hping_command's
        and _mobile_command's `timeout N <generator> >LOG 2>&1`) --
        observed_pps alone (host-wide /proc/net/dev counters) can't
        distinguish real attack traffic from incidental management/SSH
        chatter, so a generator that silently failed to launch could
        otherwise still be accepted as a confirmed NO_DETECTION. Returns
        False only on a recognized failure marker; True when the log was
        read and had none; None (never a failure) when there's no such
        per-run log for this domain at all (broadband's FIFO-driven
        agent has no per-run file -- see run_trial()'s own broadband
        recovery note for the same "not every domain has every signal"
        pattern) or the log itself could not even be read."""
        if self.dry_run or domain == "broadband":
            return None
        hosts = (ENTERPRISE_MULTIDOMAIN_HOSTS if domain == "enterprise" and vector == "MULTIDOMAIN_FLOOD"
                 else (HOST_BY_DOMAIN[domain],))
        read_any = False
        for host in hosts:
            try:
                out = self.shell(host, f"cat /tmp/ddos-trial-{run_id}.log 2>/dev/null; true", timeout=10)
            except (LabError, subprocess.TimeoutExpired):
                continue
            read_any = True
            if any(marker in out for marker in self._GENERATOR_ERROR_MARKERS):
                return False
        return True if read_any else None

    # vector -> the (dst_port, protocol) _hping_command()/_mobile_command()
    # actually target -- used by mitigation_withdrawn() below to look up
    # the SPECIFIC rule a trial's own mitigation should have created,
    # not just "is anything blocked". 0 for ICMP, which carries no port.
    _EXPECTED_BLOCK_TUPLE = {
        "TCP_SYN_FLOOD": (443, "TCP"),
        "UDP_FLOOD": (53, "UDP"),
        "MULTIDOMAIN_FLOOD": (53, "UDP"),
        "ICMP_FLOOD": (0, "ICMP"),
    }

    def mitigation_withdrawn(self, vector: str, src_ip: str, dst_ip: str) -> Optional[bool]:
        """2nd review pass, finding 4: a successful TCP:80 probe
        (check_traffic_recovery) proves the victim's HTTP service is
        reachable again -- it does NOT prove the SPECIFIC rule this
        trial's own attack triggered (TCP/443 or UDP/53, _EXPECTED_
        BLOCK_TUPLE above) was ever actually withdrawn; a stale/wrongly-
        scoped block on that exact 5-tuple could coexist with port 80
        working fine. Queries the controller's own /api/blocks (web/
        api.py, backed by OrchestrationController._sync_dashboard_blocks
        -- the same source of truth `/api/blocks` returns to a human
        looking at the dashboard) from orchestrator itself (loopback,
        port 5000 -- see web/socket_server.py's own start_server()) and
        checks whether a block matching this trial's own (src_ip, dst_ip,
        dst_port, protocol) is still present. None (never a failure) when
        src_ip is empty (a wildcard/distributed row -- see MULTIDOMAIN_
        FLOOD's own enterprise source handling, no single 5-tuple to look
        up) or the API couldn't be reached/parsed at all."""
        if self.dry_run or not src_ip:
            return None
        dst_port, protocol = self._EXPECTED_BLOCK_TUPLE.get(vector, (0, ""))
        try:
            out = self.shell("orchestrator", "curl -s http://127.0.0.1:5000/api/blocks", timeout=10)
            blocks = json.loads(out)
        except (LabError, subprocess.TimeoutExpired, ValueError):
            return None
        if not isinstance(blocks, list):
            return None
        still_blocked = any(
            isinstance(b, dict) and b.get("src_ip") == src_ip and b.get("dst_ip") == dst_ip
            and (dst_port == 0 or b.get("dst_port") == dst_port)
            and str(b.get("protocol", "")).upper() == protocol
            for b in blocks
        )
        return not still_blocked

    def healthy(self, host: str, command: str) -> bool:
        try:
            self.shell(host, command)
            return True
        except (LabError, subprocess.TimeoutExpired):
            return False

    def ensure_vm_reachable(self, host: str, vm_name: str) -> None:
        """Recover an unreachable VM through the lab's configured govc path."""
        for _ in range(3):
            if self.healthy(host, "true"):
                return
            time.sleep(3)

        env_candidates = (
            self.repo / "deploy/vm-lab/.govc.env",
            Path.home() / "isp-ddos-ryu/deploy/vm-lab/.govc.env",
        )
        env_file = next((path for path in env_candidates if path.is_file()), None)
        if env_file is None:
            raise LabError(f"{host} is unreachable and .govc.env was not found")

        env_q = shlex.quote(str(env_file))
        vm_q = shlex.quote(vm_name)
        command = (
            f"set -a; . {env_q}; set +a; "
            f"state=$(govc vm.info {vm_q} | awk '/Power state:/ {{print $3}}'); "
            f"if [ \"$state\" = poweredOff ]; then govc vm.power -on {vm_q}; "
            f"elif [ \"$state\" != poweredOn ]; then exit 2; fi"
        )
        self._run(["bash", "-lc", command], timeout=90)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if self.healthy(host, "true"):
                return
            time.sleep(5)
        raise LabError(
            f"{host} remains unreachable; VM {vm_name} is powered on and was not force-restarted"
        )

    def log_size(self) -> int:
        if self.dry_run:
            return 0
        out = self.shell("orchestrator", "stat -c %s /var/log/ryu-manager.log")
        values = re.findall(r"(?m)^\s*(\d+)\s*$", out)
        if not values:
            raise LabError("could not read ryu-manager.log size")
        return int(values[-1])

    def log_from(self, offset: int) -> str:
        # tail -c is 1-based: byte offset N is read with -c +(N+1).
        return self.shell(
            "orchestrator",
            f"tail -c +{offset + 1} /var/log/ryu-manager.log",
            timeout=60,
        )

    @staticmethod
    def marker_path(run_id: str, domain: str) -> str:
        return f"/tmp/ddos-trial-{run_id}-{domain}.start"

    def _hping_command(self, domain: str, vector: str, run_id: str,
                       duration: int) -> str:
        marker = self.marker_path(run_id, domain)
        if vector in ("UDP_FLOOD", "MULTIDOMAIN_FLOOD"):
            args = f"--udp --keep -p 53 -i u1000 {TARGET_IP}"
        elif vector == "TCP_SYN_FLOOD":
            # Keep one source port so softflowd tracks one flow instead
            # of one flow per packet. This preserves the aggregate rate
            # and avoids delaying NetFlow export behind thousands of
            # short-lived records in the Peering domain.
            args = f"-S --keep -p 443 -i u1000 {TARGET_IP}"
        elif vector == "ICMP_FLOOD":
            args = f"--icmp -i u1000 {TARGET_IP}"
        else:
            raise LabError(f"unsupported vector: {vector}")
        return (
            f"date +%s.%N > {marker}; "
            f"timeout {duration} hping3 {args} "
            f">/tmp/ddos-trial-{run_id}.log 2>&1"
        )

    def _mobile_command(self, vector: str, run_id: str, duration: int) -> str:
        # hping3 does NOT work over srsue's tun_srsue interface -- it is
        # POINTOPOINT/NOARP, the same class of L2-framing mismatch that
        # already ruled out hping3 for the broadband domain's own
        # interfaces (see simulation/bng_flood.py's module docstring).
        # Mirrors that script's kernel-socket approach instead, pushed to
        # the UE host and run inside ue1's netns.
        marker = self.marker_path(run_id, "mobile")
        # The heredoc's closing delimiter MUST be alone on its own line --
        # a trailing "\n" here is load-bearing, not cosmetic. Appending
        # ";" straight after "PYEOF" would put the terminator and the
        # next command on the same line, which the shell doesn't
        # recognize as the end of the heredoc at all (confirmed on a
        # real run: dash warns "here-document ... delimited by end-of-
        # file" and the whole rest of the command gets swallowed as part
        # of the file content instead of executing).
        push = f"cat > /tmp/mobile_flood.py <<'PYEOF'\n{_MOBILE_FLOOD_SCRIPT}\nPYEOF\n"
        if vector == "ICMP_FLOOD":
            inner = f"ip netns exec ue1 ping -f -q -W1 {TARGET_IP}"
        else:
            proto = "udp" if vector in ("UDP_FLOOD", "MULTIDOMAIN_FLOOD") else "syn"
            dst_port = 53 if proto == "udp" else 443
            inner = f"ip netns exec ue1 python3 /tmp/mobile_flood.py {proto} {TARGET_IP} {dst_port}"
        return (
            f"{push}"
            f"date +%s.%N > {marker}; "
            f"timeout {duration} {inner} >/tmp/ddos-trial-{run_id}.log 2>&1"
        )

    def launch(self, domain: str, vector: str, run_id: str, duration: int) -> None:
        marker = self.marker_path(run_id, domain)
        if domain == "enterprise" and vector == "MULTIDOMAIN_FLOOD":
            # Item 7 fix -- see ENTERPRISE_MULTIDOMAIN_HOSTS's own
            # comment: one attacker alone can never cross
            # settings.DIST_MIN_SOURCES, so this scenario fans out to all
            # 5 ent-site-N hosts instead of just HOST_BY_DOMAIN's one.
            for site in ENTERPRISE_MULTIDOMAIN_HOSTS:
                self.shell(site, self._hping_command(domain, vector, run_id, duration),
                           background=True)
            return
        host = HOST_BY_DOMAIN[domain]
        if domain == "broadband":
            scenario = {
                "TCP_SYN_FLOOD": "syn_flood",
                "UDP_FLOOD": "udp_flood",
                "ICMP_FLOOD": "icmp_flood",
                "MULTIDOMAIN_FLOOD": "udp_flood",
            }[vector]
            # The marker is written by the same shell that writes the FIFO.
            command = (
                f"date +%s.%N > {marker}; "
                f"printf '%s\\n' 'attack {scenario}' > /run/bng-agent/cmd"
            )
            self.shell(host, command)
        elif domain == "mobile":
            self.shell(host, self._mobile_command(vector, run_id, duration),
                       background=True)
        else:
            self.shell(host, self._hping_command(domain, vector, run_id, duration),
                       background=True)

    def attack_start(self, domain: str, run_id: str, vector: str = "") -> float:
        if self.dry_run:
            return time.time()
        # Item 7 fix: enterprise's MULTIDOMAIN_FLOOD writes a marker on
        # each of its 5 hosts (launch()'s own fan-out) -- the earliest of
        # the 5 is this trial's real attack-onset time, same idea as a
        # single-host read for every other domain/vector.
        hosts = (ENTERPRISE_MULTIDOMAIN_HOSTS if domain == "enterprise" and vector == "MULTIDOMAIN_FLOOD"
                 else (HOST_BY_DOMAIN[domain],))
        starts = []
        for host in hosts:
            out = self.shell(host, f"cat {self.marker_path(run_id, domain)}")
            matches = re.findall(r"(?m)^\s*(\d+\.\d+)\s*$", out)
            if matches:
                starts.append(float(matches[-1]))
        if not starts:
            raise LabError(f"missing attack start marker for {domain}")
        return min(starts)

    def stop(self, domain: str) -> None:
        if domain == "enterprise":
            # Always all 5 (idempotent/harmless on a host that was never
            # attacking) -- simpler than threading `vector` through
            # cleanup()'s own domain-only signature just for this.
            for site in ENTERPRISE_MULTIDOMAIN_HOSTS:
                self.shell(site, "pkill -f '[h]ping3' || true", check=False)
            return
        host = HOST_BY_DOMAIN[domain]
        if domain == "broadband":
            self.shell(host, "printf '%s\\n' baseline > /run/bng-agent/cmd", check=False)
        elif domain == "mobile":
            self.shell(
                host,
                "pkill -f '[m]obile_flood.py' 2>/dev/null; "
                f"pkill -f '[p]ing -f -q -W1 {TARGET_IP}' 2>/dev/null; true",
                check=False,
            )
        else:
            self.shell(host, "pkill -f '[h]ping3' || true", check=False)

    def cleanup(self, domains: tuple = DOMAINS) -> None:
        """`domains` (2nd review pass, finding 5 -- same scoping as
        healthcheck()/startup_healthcheck()) -- this used to always stop
        every domain's generator regardless of what was actually
        selected, which could delay or disturb a domain's traffic that a
        campaign never touched at all (e.g. pkilling hping3 on every
        ent-site-N host even for a Mobile-only --domains run)."""
        for domain in domains:
            self.stop(domain)

    def mobile_chain_healthy(self) -> bool:
        """CU1(`ran`)/DU1(`du`)/UE1 chain health, by each component's OWN
        log/process (deploy/vm-lab/webtool/status_checks.py's own
        validated probes, mobile-bringup-order memory) -- never e2mgr's
        connectionStatus (frequently stale) or a raw SCTP-association
        grep (the old pre-oran-sc-ric-migration port, 38472, isn't even
        the RIC's current E2 port -- 36421). Shared by startup_
        healthcheck() (once, at campaign start) and mobile_preflight()
        (before every single mobile trial, item 2) -- exceptions never
        escape, a probe that can't even run counts as unhealthy."""
        try:
            return (
                self.healthy("ran", "pgrep -f '^srscu -c' >/dev/null")
                and self.healthy("du", "pgrep -f '^srsdu -c' >/dev/null && "
                                 "grep -q 'E2 Setup procedure successful' /tmp/du.log")
                and self.healthy("ue", "systemctl is-active ue1 >/dev/null && "
                                 "ip netns exec ue1 test -d /sys/class/net/tun_srsue && "
                                 f"ip netns exec ue1 ping -c 2 -W 3 {TARGET_IP}")
            )
        except Exception:  # noqa: BLE001
            return False

    def healthcheck(self, domains: tuple = DOMAINS) -> None:
        """`domains` (item 2 fix, same as startup_healthcheck) -- this is
        also called once per trial in the main iteration loop, so an
        Enterprise/Peering-only campaign must not be able to fail (or be
        slowed down retrying) over `br`/`bng`/`suscriptor`, which only
        the broadband/peering domains actually use."""
        checks = [("orchestrator", "systemctl is-active ryu-manager nfcapd exabgp")]
        if "peering" in domains:
            checks.append(("br", "systemctl is-active softflowd-peering"))
        if "broadband" in domains:
            checks.append(("bng", "systemctl is-active accel-pppd freeradius"))
            checks.append(("suscriptor", "systemctl is-active bng-subscriber-agent"))
        for host, command in checks:
            out = self.shell(host, command)
            if self.dry_run:
                continue
            active = re.findall(r"(?m)^active$", out)
            expected = 3 if host == "orchestrator" else (2 if host == "bng" else 1)
            if len(active) < expected:
                raise LabError(f"health check failed on {host}: {out.strip()}")

    # Hosts each domain's startup healthcheck needs beyond the always-
    # needed orchestrator/victim (item 2 fix: this used to be one fixed
    # list checked regardless of --domains, so a Mobile-only VM outage
    # could block/slow down an Enterprise-only or Peering-only campaign
    # that never touches Mobile at all).
    _DOMAIN_HOSTS = {
        "enterprise": ("ent-site-1", "pe"),
        "broadband": ("bng", "suscriptor"),
        "mobile": ("ric", "core5g", "ran", "du", "ue"),
        "peering": ("br", "peer-router"),
    }

    def startup_healthcheck(self, domains: tuple = DOMAINS) -> None:
        """Validate the selected domains and repair only the parts that
        are unhealthy. `domains` (item 2 fix) scopes BOTH which VMs are
        checked for reachability and which domain-specific blocks below
        run at all -- a campaign that never selected "mobile" must never
        be blocked, slowed down, or failed by Mobile's own, separately
        known flakiness."""
        if self.dry_run:
            self.healthcheck(domains)
            return

        print("\n=== startup healthcheck: VM availability ===", flush=True)
        hosts = {"orchestrator", "victim"}
        for domain in domains:
            hosts.update(self._DOMAIN_HOSTS[domain])
        # Mobile's own hosts are handled tolerantly here (2nd review pass,
        # finding 5) -- a VM-level unreachability (ensure_vm_reachable's
        # own govc-recovery attempt failed, not just a process inside it)
        # used to raise straight out of this loop and abort the whole
        # campaign before ever reaching the "mobile" block's own tolerant
        # retry further down, even though that block already exists
        # specifically to NOT let Mobile's known flakiness take the other
        # domains down with it. mobile_chain_healthy() below calls
        # self.healthy() on ran/du/ue itself and already treats an
        # unreachable VM as just another unhealthy chain (caught, not
        # raised) -- so this only needs to keep this loop from aborting
        # before that block gets a chance to run.
        mobile_hosts = set(self._DOMAIN_HOSTS["mobile"]) if "mobile" in domains else set()
        for host in sorted(hosts):
            if host in mobile_hosts:
                try:
                    self.ensure_vm_reachable(host, host)
                except LabError as exc:
                    print(f"WARNING: {host} unreachable at startup ({exc}) -- "
                          "deferring to mobile's own tolerant recovery below", file=sys.stderr)
            else:
                self.ensure_vm_reachable(host, host)

        print("\n=== startup healthcheck: shared services ===", flush=True)
        if not self.healthy("orchestrator", "systemctl is-active ryu-manager nfcapd exabgp"):
            self.shell("orchestrator", "systemctl restart nfcapd exabgp ryu-manager", timeout=90)
        if not self.healthy("victim", f"ping -c 2 -W 2 {TARGET_IP}"):
            raise LabError("victim is not reachable at 10.55.0.100")

        if "enterprise" in domains:
            print("=== startup healthcheck: enterprise ===", flush=True)
            enterprise_ok = self.healthy("ent-site-1", f"ping -c 2 -W 2 {TARGET_IP}")
            if not enterprise_ok:
                self.playbook("deploy/vm-lab/ansible/site.yml", limit="pe,ent-site-1", timeout=300)
                self.shell("orchestrator", "systemctl restart ryu-manager", timeout=90)
                time.sleep(5)
                if not self.healthy("ent-site-1", f"ping -c 3 -W 3 {TARGET_IP}"):
                    raise LabError("enterprise recovery failed: ent-site-1 cannot reach victim")

        if "broadband" in domains:
            print("=== startup healthcheck: broadband ===", flush=True)
            broadband_services = (
                self.healthy("bng", "systemctl is-active accel-pppd freeradius")
                and self.healthy("suscriptor", "systemctl is-active bng-subscriber-agent")
            )
            broadband_sessions = broadband_services and self.broadband_session_count() == 8
            if not broadband_sessions:
                self.shell("bng", "systemctl restart freeradius accel-pppd", timeout=90)
                self.shell("suscriptor", "systemctl restart bng-subscriber-agent", timeout=90)
                self.wait_for_baseline(("broadband",), timeout=150)

        if "mobile" in domains:
            print("=== startup healthcheck: mobile ===", flush=True)
            if not self.mobile_chain_healthy():
                for attempt in range(1, 4):
                    # Targeted recovery only (cu1/du1/ue1) -- reconnect_mobile_
                    # domain.yml also covers du2-5/ue2-5/cu2, which this
                    # single-attacker trial design doesn't touch, matching how
                    # enterprise/broadband recovery above is likewise scoped
                    # to just their one representative source. power_cycle is
                    # explicitly false: a full power-off/on of the whole
                    # mobile domain is a last resort the user runs by hand
                    # (see mobile-bringup-order memory), not something a
                    # statistical-trial retry loop should ever trigger.
                    #
                    # Wrapped in try/except (item 2 bug fix): this call used
                    # to be unguarded, so a LabError/timeout from the
                    # playbook itself (not just "ran but didn't fix it")
                    # propagated straight out of startup_healthcheck() and
                    # crashed the whole campaign process before it even
                    # started -- unlike mobile_preflight()'s own per-trial
                    # recovery, which already caught exactly this.
                    try:
                        self.playbook(
                            "deploy/vm-lab/ansible/playbooks/reconnect_mobile_domain.yml",
                            limit="ran,du,ue", tags="cu1,du1,ue1",
                            extra_vars={"power_cycle": "false"}, timeout=360,
                        )
                    except Exception as exc:  # noqa: BLE001
                        print(f"WARNING: mobile recovery attempt {attempt}/3 raised: {exc}",
                              file=sys.stderr)
                    if self.mobile_chain_healthy():
                        break
                else:
                    # NOT a hard raise, deliberately -- the mobile domain's
                    # ZMQ RACH is known non-deterministic (mobile-bringup-
                    # order memory: real recovery sometimes needs a full
                    # power-cycle this targeted retry can't do). Printing and
                    # continuing lets the other domains' trials still run;
                    # mobile's own trials will simply come back INCOMPLETE
                    # (extract_result already handles a missing detection).
                    print(
                        "WARNING: mobile recovery did not succeed after 3 attempts "
                        "(cu1/du1/ue1) -- continuing anyway, mobile trials may be "
                        "INCOMPLETE. See mobile-bringup-order memory for a manual "
                        "full power-cycle if this persists.",
                        file=sys.stderr,
                    )

        if "peering" in domains:
            print("=== startup healthcheck: peering ===", flush=True)
            peering_check = (
                "systemctl is-active bird && "
                "birdc show protocols | grep -qE 'br[[:space:]]+BGP.*Established' && "
                f"ping -c 2 -W 2 {TARGET_IP}"
            )
            peering_ok = (
                self.healthy("br", "systemctl is-active softflowd-peering")
                and self.healthy("peer-router", peering_check)
            )
            if not peering_ok:
                self.playbook(
                    "deploy/vm-lab/ansible/site.yml",
                    limit="br,peer-router,victim", timeout=300,
                )
                self.shell("orchestrator", "systemctl restart nfcapd exabgp ryu-manager", timeout=90)
                for _ in range(12):
                    time.sleep(5)
                    if self.healthy("peer-router", peering_check):
                        break
                else:
                    raise LabError(
                        "peering recovery failed: BGP is not established or victim is unreachable"
                    )

        self.healthcheck(domains)
        print("=== startup healthcheck: selected domains healthy ===\n", flush=True)

    def broadband_session_count(self) -> int:
        out = self.shell("bng", "accel-cmd -p 2000 show sessions")
        return len(re.findall(r"(?m)^\s*ipoe\d+\s+\|.*\|\s+active\s+\|", out))

    def wait_for_baseline(self, domains=DOMAINS, timeout: int = 120) -> None:
        if self.dry_run:
            return
        if "broadband" not in domains:
            return
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if self.broadband_session_count() == 8:
                    return
            except LabError:
                pass
            time.sleep(5)
        raise LabError("broadband did not recover 8/8 active IPoE sessions")


def parse_ts(value: str) -> float:
    value = value.replace(",", ".")
    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in value else "%Y-%m-%d %H:%M:%S"
    return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).timestamp()


def iso(epoch: Optional[float]) -> str:
    if epoch is None:
        return ""
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds")


def canonical_domain(log_domain: str) -> str:
    return "peering" if log_domain.lower() == "bgp" else log_domain.lower()


def source_matches(domain: str, expected: str, observed: str) -> bool:
    if observed == "*":
        # Accepted for ANY domain now (2nd review pass, finding 1):
        # controller/ryu_controller_2.py emits one ATTACK_DETECTED line
        # PER CONTRIBUTING DOMAIN for a DDOS_DISTRIBUTED/MULTIDOMAIN_
        # DISTRIBUTED_ATTACK detection (DetectionResult.source_domains'
        # real per-source attribution), not just one line under
        # whichever domain _pick_representative() happened to choose --
        # so a line's own [domain] bracket is now architecturally
        # guaranteed to be a domain that genuinely contributed sources.
        # Previously restricted to ("broadband", "enterprise") because
        # ONLY those two domains could ever end up as the representative
        # for their own multi-source attack; now that every contributing
        # domain gets its own correctly-bracketed line, that restriction
        # would just as wrongly reject a real Mobile/Peering line.
        return True
    return not expected or observed == expected


def extract_result(log: str, result: TrialResult, attack_epoch: float) -> TrialResult:
    detection = mitigation = recovery = None
    detected_source = result.source

    for line in log.splitlines():
        m = DETECTION_RE.search(line)
        if m and canonical_domain(m.group("domain")) == result.domain and m.group("dst") == result.target:
            if source_matches(result.domain, result.source, m.group("src")):
                detection = detection or parse_ts(m.group("ts"))
                if m.group("src") != "*":
                    detected_source = m.group("src")
            continue
        m = MITIGATION_RE.search(line)
        if m and canonical_domain(m.group("domain")) == result.domain:
            if source_matches(result.domain, detected_source, m.group("src")):
                mitigation = mitigation or parse_ts(m.group("ts"))
            continue
        m = RECOVERY_RE.search(line)
        if m and canonical_domain(m.group("domain")) == result.domain:
            if source_matches(result.domain, detected_source, m.group("src")):
                recovery = recovery or parse_ts(m.group("ts"))

    result.source = detected_source
    result.attack_at = iso(attack_epoch)
    result.detection_at = iso(detection)
    result.mitigation_at = iso(mitigation)
    result.recovery_at = iso(recovery)
    if detection is not None:
        result.Td_s = round(max(0.0, detection - attack_epoch), 3)
    if detection is not None and mitigation is not None:
        result.Tm_s = round(max(0.0, mitigation - detection), 3)
    if mitigation is not None and recovery is not None:
        result.Tr_s = round(max(0.0, recovery - mitigation), 3)
    missing = [name for name, value in (("detection", detection), ("mitigation", mitigation), ("recovery", recovery)) if value is None]
    if not missing:
        result.status = "OK"
        result.error = ""
    elif (
        detection is None and mitigation is None and recovery is None
        and result.observed_pps is not None and result.observed_pps >= MIN_CONFIRMED_ATTACK_PPS
        and result.generator_confirmed is not False
    ):
        # Item 7 fix: a genuine "the attack ran but nothing detected it"
        # outcome is a VALID experimental result for an A/B sensitivity
        # comparison (isolated vs. multidomain detection), not a script
        # failure -- it used to come back as the same generic
        # "INCOMPLETE" a real pipeline bug (e.g. detected-but-never-
        # mitigated) produces, which main()'s own loop treats as fatal
        # and aborts the whole campaign on. Distinguished here from that
        # case by requiring INDEPENDENT confirmation the attack actually
        # sent traffic -- not just "no detection line appeared", which
        # could equally mean the attack itself never launched.
        #
        # 2nd review pass, finding 2 -- observed_pps > 0 alone was too
        # weak a bar: Lab.sample_tx_packets() sums EVERY non-loopback
        # interface's tx_packets, which includes this very SSH/ansible
        # management traffic, not just the attack -- a generator that
        # silently never launched could still read nonzero from
        # incidental chatter alone. Now requires a MEANINGFUL floor
        # (MIN_CONFIRMED_ATTACK_PPS, comfortably above plain management
        # traffic) AND generator_confirmed is not False (Lab.
        # generator_confirmed()'s own read of the generator's PER-RUN log
        # for a recognized failure marker -- None, e.g. broadband with no
        # such log, never vetoes this on its own).
        #
        # A detection that DID fire but whose mitigation/recovery never
        # followed stays "INCOMPLETE" on purpose -- that is a real
        # pipeline-bug symptom (e.g. the peering FLOWSPEC bug found
        # earlier in this campaign) and must keep halting the campaign.
        result.status = "NO_DETECTION"
        result.error = (
            f"attack confirmed (observed_pps={result.observed_pps}, "
            f"generator_confirmed={result.generator_confirmed}) but no "
            "ATTACK_DETECTED logged within the event window"
        )
    else:
        result.status = "INCOMPLETE"
        result.error = "missing " + ", ".join(missing)
    return result


def append_checkpoint(path: Path, rows: Iterable[TrialResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(asdict(row), sort_keys=True) + "\n")
        f.flush()


def load_checkpoint(path: Path) -> list[TrialResult]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(TrialResult(**json.loads(line)))
    return rows


def write_outputs(out_dir: Path, rows: list[TrialResult]) -> None:
    fields = list(TrialResult.__dataclass_fields__)
    with (out_dir / "trials_long.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)

    metric_fields = [f"{vector}_{metric}" for vector in VECTORS for metric in ("Td", "Tm", "Tr")]
    by_key = {(r.domain, r.iteration, r.vector): r for r in rows}
    with (out_dir / "trials_table.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["Dominio", "Corrida", *metric_fields]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for domain in DOMAINS:
            iterations = sorted({r.iteration for r in rows if r.domain == domain})
            for iteration in iterations:
                record = {"Dominio": domain, "Corrida": iteration}
                for vector in VECTORS:
                    row = by_key.get((domain, iteration, vector))
                    for metric in ("Td", "Tm", "Tr"):
                        record[f"{vector}_{metric}"] = "" if row is None else getattr(row, f"{metric}_s")
                writer.writerow(record)


def wait_and_collect(lab: Lab, offset: int, results: list[TrialResult], starts: dict[str, float],
                     timeout: int, poll: int) -> list[TrialResult]:
    deadline = time.monotonic() + timeout
    latest = ""
    while time.monotonic() < deadline:
        latest = lab.log_from(offset)
        parsed = [extract_result(latest, row, starts[row.domain]) for row in results]
        if all(row.status == "OK" for row in parsed):
            return parsed
        time.sleep(poll)
    # Fetch once after the deadline so an event emitted during the final sleep
    # is not discarded merely because it fell between polling instants.
    latest = lab.log_from(offset)
    return [extract_result(latest, row, starts[row.domain]) for row in results]


def _tcp_recovery_probe_cmd(netns: str = "", device: str = "") -> str:
    """Item 4 fix: a TCP connect to the victim's REAL listening service
    (roles/victim's victim-http, port 80) instead of ICMP ping. A ping
    reply only proves ICMP reachability -- it says nothing about whether
    the TCP/UDP service the attack actually targeted (and the mitigation
    actually blocked/throttled) is reachable again, and in principle the
    victim could answer ICMP while port 80 stays unreachable (e.g. a
    stale conntrack/NAT entry, or a block the mitigation scoped to the
    wrong port). bash's /dev/tcp pseudo-device needs no extra package on
    any of these hosts (confirmed Ubuntu 22.04 -- see enterprise_site/
    peer_router/ue_srsue roles' own `apt` tasks; none of them install
    curl/wget) and a bare TCP SYN/ACK/FIN is enough to prove the path
    and the service are both up, without needing an HTTP client.
    `device` (SO_BINDTODEVICE via a tiny inline python3, root required --
    every lab.shell() call already runs with -b/become) sources the
    probe out one specific interface -- needed for broadband, where the
    host itself (`suscriptor`) has no single IP of its own; `netns` runs
    it inside a mobile UE's network namespace instead."""
    if device:
        probe = (
            "python3 -c \"import socket,sys\n"
            "s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            f"s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'{device}')\n"
            "s.settimeout(3)\n"
            "try:\n"
            f"    s.connect(('{TARGET_IP}', 80))\n"
            "except OSError:\n"
            "    sys.exit(1)\n"
            "finally:\n"
            "    s.close()\n\""
        )
    else:
        probe = f'timeout 3 bash -c "echo > /dev/tcp/{TARGET_IP}/80"'
    return f"ip netns exec {netns} {probe}" if netns else probe


# Legitimate-traffic recovery probe, from the SAME source the attack
# used -- see check_traffic_recovery()'s own docstring (item 5: a Tr_s
# timestamp only proves a MITIGATION->UNBLOCK pair was logged, not that
# the legitimate source can actually reach the target again).
_RECOVERY_PROBE = {
    "enterprise": ("ent-site-1", _tcp_recovery_probe_cmd()),
    "peering": ("peer-router", _tcp_recovery_probe_cmd()),
    "mobile": ("ue", _tcp_recovery_probe_cmd(netns="ue1")),
    # broadband (item 4 fix): previously had NO probe at all here --
    # wait_for_baseline()'s 8-active-session count proves accel-ppp
    # sessions exist, not that legitimate traffic actually passes
    # through one. macvlan1 (subscriber #1) is always one of the
    # attacking sources whenever bng_subscriber_agent.py launches any
    # scenario (SubscriberPool.launch() iterates range(1, active_count+
    # 1)), so it's a real, representative post-mitigation probe --
    # bound to that interface specifically (suscriptor itself has no
    # single stable own-IP the way the other domains' hosts do).
    "broadband": ("suscriptor", _tcp_recovery_probe_cmd(device="macvlan1")),
}


def mobile_preflight(lab: Lab) -> Tuple[bool, str]:
    """Item 2 -- checked before EVERY mobile trial (Lab.mobile_chain_healthy()
    is cheap: a handful of SSH round trips, not a full bring-up). On a
    failed chain, ONE bounded, targeted recovery attempt
    (reconnect_mobile_domain.yml --tags cu1,du1,ue1, power_cycle=false --
    same scope as startup_healthcheck()'s own recovery, just a single
    attempt instead of 3 to keep the per-trial cost bounded over a long
    campaign). Any exception the recovery attempt raises is CAUGHT here
    and turned into an invalidation reason -- it must never propagate
    and crash the whole campaign process over one domain's known
    flakiness (mobile-bringup-order memory)."""
    if lab.dry_run or lab.mobile_chain_healthy():
        return True, ""
    try:
        lab.playbook(
            "deploy/vm-lab/ansible/playbooks/reconnect_mobile_domain.yml",
            limit="ran,du,ue", tags="cu1,du1,ue1",
            extra_vars={"power_cycle": "false"}, timeout=300,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"mobile recovery raised: {exc}"
    if lab.mobile_chain_healthy():
        return True, ""
    return False, "cu1/du1/ue1 chain still unhealthy after 1 targeted recovery attempt"


def check_traffic_recovery(lab: Lab, domain: str) -> Optional[bool]:
    """Sends real traffic from the attack's own source, right after
    Tr_s, and reports whether it reached the target. None (not False)
    when this domain has no such probe defined above -- a missing
    measurement must never be reported as a failed one."""
    probe = _RECOVERY_PROBE.get(domain)
    if probe is None or lab.dry_run:
        return None
    host, cmd = probe
    return lab.healthy(host, cmd)


def run_trial(lab: Lab, iteration: int, vector: str, domains: tuple[str, ...],
              attack_duration: int, event_timeout: int, poll: int,
              scenario_mode: str = "") -> list[TrialResult]:
    run_id = f"i{iteration:03d}-{vector.lower()}-{uuid.uuid4().hex[:8]}"
    results = [
        TrialResult(
            run_id, iteration, domain, vector,
            # "" (wildcard, matched via source_matches's own `not expected`
            # branch), not SOURCE_HINT, for enterprise's MULTIDOMAIN_FLOOD
            # (item 7 fix) -- it now launches from 5 distinct ent-site-N
            # sources, not just the one SOURCE_HINT names, so pinning the
            # expected source to a single IP would miss a detection
            # reported against any of the other 4.
            "" if (domain == "enterprise" and vector == "MULTIDOMAIN_FLOOD") else SOURCE_HINT.get(domain, ""),
            TARGET_IP,
            code_version=lab.code_version(), detection_mode=lab.detection_mode,
            scenario_mode=scenario_mode,
        )
        for domain in domains
    ]

    # Item 2 -- check the CU/DU/UE chain before EVERY mobile trial (not
    # just once at campaign start), only when mobile is actually one of
    # this trial's domains. A failed chain gets ONE bounded, captured
    # recovery attempt (mobile_preflight() never lets a recovery
    # exception escape uncaught) before this trial is given up on.
    #   - isolated trial (mobile alone): invalidate ONLY mobile's own
    #     row ("INVALID") -- the other domains in this iteration/vector
    #     run as their own separate isolated trials and are unaffected.
    #   - joint scenario (mobile + others, i.e. MULTIDOMAIN_FLOOD):
    #     invalidate the WHOLE scenario ("INVALID_SCENARIO") -- a 3-of-4
    #     -domain attack is not the 4-domain coordinated event this
    #     scenario is meant to measure, so none of its rows may be
    #     counted as one.
    if "mobile" in domains:
        mobile_ok, reason = mobile_preflight(lab)
        if not mobile_ok:
            status = "INVALID" if len(domains) == 1 else "INVALID_SCENARIO"
            for row in results:
                row.status = status
                row.error = f"mobile preflight failed: {reason}"
            return results

    offset = lab.log_size()
    starts: dict[str, float] = {}
    tx_before: dict[str, Optional[int]] = {}
    try:
        # Real wall-clock bracket for observed_pps below (minor fix from
        # the same review pass) -- NOT a hardcoded `attack_duration + 1`,
        # which undercounts the actual window: tx_before is sampled here,
        # BEFORE launch()'s own SSH round trips, and tx_after is sampled
        # only after attack_duration's sleep on top of THAT -- the real
        # elapsed time is measurably longer than attack_duration + 1 once
        # launch/attack_start's own remote calls are accounted for, which
        # a fixed constant silently ignored.
        tx_before_at: dict[str, float] = {}
        for d in domains:
            tx_before[d] = lab.sample_tx_packets(d, vector)
            tx_before_at[d] = time.monotonic()
        # Async hping launches keep multidomain starts close together; broadband's
        # FIFO write is synchronous and takes only one local operation.
        # A multidomain trial is one sequential experiment, but its one source
        # per domain must start concurrently so the correlation windows truly
        # overlap.  Individual trials also pass through this same path.
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(domains)) as pool:
            futures = {
                pool.submit(lab.launch, domain, vector, run_id, attack_duration): domain
                for domain in domains
            }
            for future in concurrent.futures.as_completed(futures):
                future.result()
        for domain in domains:
            starts[domain] = lab.attack_start(domain, run_id, vector)
        if lab.dry_run:
            for row in results:
                row.attack_at = iso(starts[row.domain])
                row.status = "DRY_RUN"
                row.error = "commands validated but not executed"
            return results

        # Bracket the attack window to measure the ACHIEVED rate (item 6:
        # "tasas observadas") -- not the configured/intended one. Sleeping
        # past attack_duration (the remote `timeout N` wrapper self-stops
        # the flood by then) keeps this a clean before/after pair instead
        # of racing lab.stop()'s own kill in the `finally` below.
        time.sleep(attack_duration + 1)
        if "broadband" in domains:
            # 2nd review pass, finding 3: broadband's launch() just sends
            # 'attack <scenario>' to bng_subscriber_agent's FIFO -- unlike
            # every hping3/mobile-flood invocation, which is wrapped in
            # `timeout {duration} ...` and self-stops, the agent keeps
            # the generator running until it receives a DIFFERENT command
            # (this method's own `finally: lab.stop(domain)` below, which
            # only runs once wait_and_collect()'s full event_timeout has
            # elapsed). That let broadband keep attacking well past
            # attack_duration -- through the detection/mitigation wait
            # AND the recovery probe -- while every other domain's
            # generator had already self-stopped, breaking comparability
            # across domains and risking a SECOND, spurious re-detection/
            # re-mitigation cycle before this trial even finishes
            # evaluating the first one. Stopped explicitly here, at the
            # same point every other domain's `timeout` wrapper already
            # stops itself, BEFORE detection/mitigation/recovery are
            # evaluated below.
            lab.stop("broadband")
        for domain in domains:
            after = lab.sample_tx_packets(domain, vector)
            after_at = time.monotonic()
            before = tx_before.get(domain)
            # Minor fix (2nd review pass): each domain's own before/after
            # pair is bracketed by ITS OWN two timestamps now, not one
            # `elapsed` shared across every domain computed before any of
            # them had even been sampled -- sample_tx_packets() calls are
            # sequential (one SSH round trip per domain/host), so by the
            # time the last domain in a multidomain trial is sampled, its
            # real window is measurably different from the first one's.
            elapsed = after_at - tx_before_at.get(domain, after_at)
            row = next(r for r in results if r.domain == domain)
            if before is not None and after is not None and after >= before and elapsed > 0:
                row.observed_pps = round((after - before) / elapsed, 1)
            # Item 2 (2nd review pass): independent confirmation the
            # generator itself actually ran, from its own per-run log --
            # observed_pps alone can't tell real attack traffic apart
            # from incidental management/SSH chatter.
            row.generator_confirmed = lab.generator_confirmed(domain, run_id, vector)

        parsed = wait_and_collect(lab, offset, results, starts, event_timeout, poll)

        # Item 5 -- a Tr_s timestamp only means a MITIGATION->UNBLOCK pair
        # was logged; confirm the legitimate source can actually reach
        # the target again before calling it recovered. 2nd review pass,
        # finding 4 -- that HTTP probe alone doesn't prove the trial's
        # OWN rule (its specific src/dst/port/protocol) was withdrawn, so
        # mitigation_withdrawn checks that separately and explicitly,
        # instead of conflating "the web service is reachable" with "the
        # mitigation that targeted this exact 5-tuple is gone."
        for row in parsed:
            if row.status == "OK" and row.Tr_s is not None:
                row.traffic_recovered = check_traffic_recovery(lab, row.domain)
                row.mitigation_withdrawn = lab.mitigation_withdrawn(vector, row.source, row.target)
    except Exception as exc:
        for row in results:
            row.status = "ERROR"
            row.error = str(exc)
        parsed = results
    finally:
        for domain in domains:
            lab.stop(domain)
    return parsed


def run_mobile_repeatability(lab: Lab, cycles: int, attack_duration: int,
                             event_timeout: int, poll: int, checkpoint: Path,
                             out_dir: Path, previous: list[TrialResult],
                             vector: str = "UDP_FLOOD") -> list[TrialResult]:
    """Item 3 -- a single successful run only demonstrates the ran(cu1)->
    du(du1)->ue1 chain's connect->attack->detect->mitigate->release->
    recover cycle WORKS; it says nothing about whether it's STABLE
    (repeatable) across many cycles without manual intervention. This:

      1. Validates the chain once up front (mobile_preflight -- if it's
         not even up at the start, there's nothing to measure stability
         of; aborts immediately).
      2. Repeats the full cycle `cycles` times back to back. Each cycle
         IS one isolated mobile trial (run_trial), reused as-is --
         mobile_preflight's own bounded, AUTOMATED recovery attempt is
         exactly "no manual intervention needed" already; what this
         tracks on top of that is whether it was even NEEDED each time
         (lab.mobile_chain_healthy() checked BEFORE each cycle -- not
         healthy there means the previous cycle did not return the chain
         to its initial state on its own).

    Reports a stability summary at the end: cycles that completed OK,
    cycles whose traffic was confirmed to actually recover, and cycles
    that needed an intervention between them. The last number's goal is
    0 -- anything above that means the chain is not yet self-stabilizing,
    which a single successful run can never reveal.
    """
    print(f"\n=== mobile repeatability: validating the chain before cycling ===", flush=True)
    ok, reason = mobile_preflight(lab)
    if not ok:
        raise LabError(f"mobile repeatability aborted -- chain never came up: {reason}")

    # 2nd review pass, finding 6: --resume used to just re-run 1..cycles
    # unconditionally, appending NEW rows under the SAME cycle numbers
    # already in `previous` -- trials.jsonl ended up with two rows per
    # repeated cycle number (ambiguous which is "the" result for that
    # cycle) and trials_table.csv's own by_key dict silently kept only
    # the LAST one, discarding the earlier one with no indication
    # anything was lost. This CONTINUES the sequence instead: already-
    # completed cycle numbers (status OK/DRY_RUN/NO_DETECTION, matching
    # the main iteration loop's own notion of "done") are skipped, so
    # resuming a 30-cycle campaign that got to cycle 18 runs 19..30, not
    # a fresh, ambiguous 1..30 on top of what's already there.
    completed_cycles = {
        r.iteration for r in previous
        if r.domain == "mobile" and r.scenario_mode == "repeatability"
        and r.status in ("OK", "DRY_RUN", "NO_DETECTION")
    }
    if completed_cycles:
        print(f"Resuming: {len(completed_cycles)} cycle(s) already completed "
              f"({sorted(completed_cycles)}) -- running the rest.", flush=True)

    all_rows: list[TrialResult] = []
    needed_intervention = 0
    for cycle in range(1, cycles + 1):
        if cycle in completed_cycles:
            continue
        pre_healthy = lab.dry_run or lab.mobile_chain_healthy()
        if not pre_healthy:
            needed_intervention += 1
        print(
            f"\n=== mobile repeatability: cycle {cycle}/{cycles} "
            f"(chain was {'already healthy' if pre_healthy else 'UNHEALTHY -- needed an automated recovery'}) ===",
            flush=True,
        )
        rows = run_trial(lab, cycle, vector, ("mobile",), attack_duration, event_timeout, poll,
                         scenario_mode="repeatability")
        # Minor fix (same review pass): save EACH cycle as it completes,
        # not just the whole batch at the very end -- a crash/Ctrl-C
        # partway through cycle 20/30 used to lose every cycle completed
        # so far instead of leaving a resumable checkpoint, unlike the
        # main iteration loop's own per-job append_checkpoint/
        # write_outputs.
        append_checkpoint(checkpoint, rows)
        previous.extend(rows)
        write_outputs(out_dir, previous)
        all_rows.extend(rows)
        row = rows[0]
        print(
            f"  cycle {cycle}: status={row.status} Td={row.Td_s} Tm={row.Tm_s} Tr={row.Tr_s} "
            f"traffic_recovered={row.traffic_recovered}",
            flush=True,
        )
        if not lab.dry_run:
            time.sleep(5)  # brief settle between cycles -- not the full --cooldown

    # Summary covers the WHOLE campaign (cycles completed in earlier
    # --resume invocations too, via `previous`), not just this
    # invocation's own `all_rows` -- otherwise a resumed run's summary
    # would understate how much of the full `cycles` target is actually
    # done.
    full_campaign = [
        r for r in previous
        if r.domain == "mobile" and r.scenario_mode == "repeatability" and r.iteration <= cycles
    ]
    ok_cycles = sum(1 for r in full_campaign if r.status in ("OK", "DRY_RUN"))
    recovered_cycles = sum(1 for r in full_campaign if r.traffic_recovered)
    print(
        f"\n=== mobile repeatability summary: {ok_cycles}/{cycles} cycles OK, "
        f"{recovered_cycles}/{cycles} confirmed traffic-recovered, "
        f"{needed_intervention}/{cycles - len(completed_cycles)} of THIS run's cycles needed "
        "an automated recovery intervention "
        "between cycles (0 is the stability goal -- any count above that means the "
        "chain did NOT return to its initial state on its own) ===",
        flush=True,
    )
    return all_rows


def resolve_effective_vectors(mode: str, vectors: tuple[str, ...], domains: tuple[str, ...],
                              error) -> tuple[str, ...]:
    """Resolves --mode + --vectors into the actual vector set the campaign
    runs, failing fast (via `error`, expected to raise/exit) on a
    combination that can't produce any trials -- BEFORE startup_healthcheck()
    or any VM is touched, not discovered mid-run."""
    if mode == "isolated":
        effective = tuple(v for v in vectors if v != "MULTIDOMAIN_FLOOD")
        if not effective:
            error("--mode isolated needs at least one non-MULTIDOMAIN_FLOOD vector in --vectors")
        return effective
    if mode == "multidomain":
        if "MULTIDOMAIN_FLOOD" not in vectors:
            error("--mode multidomain requires MULTIDOMAIN_FLOOD in --vectors")
        if len(domains) < 2:
            error("--mode multidomain requires at least 2 --domains")
        return ("MULTIDOMAIN_FLOOD",)
    return tuple(vectors)  # "both" -- previous behavior, unchanged


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=30,
                        help="independent repetitions per domain/vector (default: 30)")
    parser.add_argument("--inventory", type=Path,
                        default=Path("deploy/vm-lab/generated/ansible/inventory.ini"))
    parser.add_argument("--output-dir", type=Path, default=Path("analysis/results/vm-lab"))
    parser.add_argument("--domains", nargs="+", choices=DOMAINS, default=list(DOMAINS))
    parser.add_argument("--vectors", nargs="+", choices=VECTORS, default=list(VECTORS))
    parser.add_argument("--mode", choices=TRIAL_MODES, default="both",
                        help="isolated: TCP/UDP/ICMP_FLOOD only, one domain per trial. "
                             "multidomain: MULTIDOMAIN_FLOOD only, needs >=2 --domains. "
                             "both (default): run --vectors as given, unchanged behavior.")
    parser.add_argument("--detection-mode", choices=("isolated", "multidomain"), default="multidomain",
                        help="isolated: each domain's telemetry analyzed on its own, no cross-domain "
                             "correlation/coordination. multidomain (default, unchanged prior behavior): "
                             "correlation.correlator.MultidomainCorrelator merges by dst_ip across domains. "
                             "Orthogonal to --mode -- the SAME attack (sources/rates/duration/target/"
                             "thresholds) runs in both; only ryu-manager's own correlation changes.")
    parser.add_argument("--attack-duration", type=int, default=20)
    parser.add_argument("--event-timeout", type=int, default=150,
                        help="seconds allowed for detection, mitigation and recovery")
    parser.add_argument("--cooldown", type=int, default=15)
    parser.add_argument("--poll", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20260925)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--repeatability-cycles", type=int, default=0,
                        help="item 3: instead of the --iterations/--vectors matrix, validate the "
                             "ran->du->ue1 chain once then repeat its full attack/detect/mitigate/"
                             "release/recover cycle this many times back to back, to check it "
                             "self-stabilizes without manual intervention. Requires --domains mobile "
                             "(exactly that, nothing else) and N>=2 (one run proves it works once, "
                             "not that it's repeatable).")
    args = parser.parse_args()
    if args.repeatability_cycles:
        if args.repeatability_cycles < 2:
            parser.error("--repeatability-cycles needs at least 2 (one cycle only shows it works once)")
        if tuple(args.domains) != ("mobile",):
            parser.error("--repeatability-cycles requires --domains mobile (exactly that, nothing else)")
    elif args.iterations < 2:
        parser.error("--iterations must be at least 2; use 30 for the thesis dataset")
    args.vectors = resolve_effective_vectors(args.mode, tuple(args.vectors), tuple(args.domains),
                                             parser.error)
    print(f"Mode: {args.mode} -- effective vectors: {', '.join(args.vectors)}", flush=True)

    repo = Path(__file__).resolve().parents[1]
    if args.inventory.is_absolute():
        inventory = args.inventory
    else:
        candidates = (
            repo / args.inventory,
            Path.home() / "isp-ddos-ryu" / args.inventory,
        )
        inventory = next((candidate for candidate in candidates if candidate.is_file()), candidates[0])
    if not inventory.is_file():
        parser.error(
            "Ansible inventory not found. Generate the VM lab inventory or pass "
            "--inventory /absolute/path/to/inventory.ini"
        )
    print(f"Using Ansible inventory: {inventory}", flush=True)
    out_dir = args.output_dir if args.output_dir.is_absolute() else repo / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = out_dir / "trials.jsonl"
    previous = load_checkpoint(checkpoint) if args.resume else []
    if checkpoint.exists() and not args.resume:
        parser.error(f"{checkpoint} already exists; use --resume or a different --output-dir")

    # Item 5 fix: a campaign manifest recording the experimental CONDITION
    # this --output-dir was started under -- --resume used to accept ANY
    # later invocation against the same directory, regardless of whether
    # --mode/--detection-mode/--domains/--vectors/--attack-duration/
    # --event-timeout actually matched the original run. A/B comparisons
    # (isolated vs. multidomain detection, or scenario mode) need those
    # to stay fixed within one directory's results -- silently mixing
    # them would make trials_long.csv/trials_table.csv average across
    # two different conditions without any way to tell which rows came
    # from which. Iterations/seed/cooldown/poll are deliberately EXCLUDED
    # -- those are allowed to differ across a resume (e.g. extending a
    # campaign to more iterations), they don't change what's being
    # measured.
    manifest_path = out_dir / "campaign_manifest.json"
    conditions = {
        "domains": sorted(args.domains),
        "vectors": sorted(args.vectors),
        "mode": args.mode,
        "detection_mode": args.detection_mode,
        "attack_duration": args.attack_duration,
        "event_timeout": args.event_timeout,
        "repeatability_cycles": args.repeatability_cycles,
    }
    if args.resume and manifest_path.exists():
        recorded = json.loads(manifest_path.read_text())
        if recorded != conditions:
            parser.error(
                f"{manifest_path} was recorded under a different experimental condition "
                "than this invocation -- --resume must not silently mix conditions in one "
                f"--output-dir (use a different --output-dir per condition):\n"
                f"  recorded:  {json.dumps(recorded, sort_keys=True)}\n"
                f"  requested: {json.dumps(conditions, sort_keys=True)}"
            )
    elif args.resume and previous and not manifest_path.exists():
        parser.error(
            f"{checkpoint} has existing results but no {manifest_path.name} (pre-dates this "
            "check) -- its original --mode/--detection-mode/--domains/--vectors/"
            "--attack-duration/--event-timeout cannot be verified against this invocation. "
            f"Confirm by hand they match, then create {manifest_path} with: "
            f"{json.dumps(conditions, sort_keys=True)}"
        )
    manifest_path.write_text(json.dumps(conditions, indent=2, sort_keys=True) + "\n")

    # Item 5 fix: the completed-run key now also carries detection_mode/
    # scenario_mode, not just (iteration, domain, vector) -- defense in
    # depth alongside the manifest check above (the manifest stops a
    # whole directory from mixing conditions; this stops a single stale
    # row from ever being mismatched against the wrong condition's
    # membership test). Item 4 fix: traffic_recovered is not False, and
    # (2nd review pass) mitigation_withdrawn is not False either -- a row
    # whose logged events all completed (status=="OK"/"NO_DETECTION") but
    # whose post-mitigation probe (HTTP reachability) OR mitigation-
    # withdrawal check (the trial's own block rule actually gone) FAILED
    # must not be treated as done; --resume should retry it like any
    # other unfinished row, not silently accept a run that never actually
    # confirmed real recovery.
    completed = {
        (r.iteration, r.domain, r.vector, r.detection_mode, r.scenario_mode)
        for r in previous
        if r.status in ("OK", "NO_DETECTION")
        and r.traffic_recovered is not False
        and r.mitigation_withdrawn is not False
    }
    lab = Lab(repo, inventory, args.dry_run)
    rng = random.Random(args.seed)

    # Set BEFORE startup_healthcheck() -- restarting ryu-manager to apply
    # a detection-mode change drops its in-memory state (active blocks),
    # so the healthcheck right after is what confirms the campaign is
    # starting from a clean, known-good state in whichever mode was asked
    # for (item 1: resolved/validated before the campaign begins, like
    # --mode's own resolve_effective_vectors()).
    lab.set_detection_mode(args.detection_mode)
    print(f"Detection mode: {args.detection_mode}", flush=True)

    lab.startup_healthcheck(tuple(args.domains))
    lab.cleanup(tuple(args.domains))
    lab.wait_for_baseline(args.domains)

    if args.repeatability_cycles:
        # Per-cycle checkpointing now happens INSIDE run_mobile_
        # repeatability itself (minor fix) -- previous/checkpoint/out_dir
        # are passed in rather than saved once at the end here.
        run_mobile_repeatability(lab, args.repeatability_cycles, args.attack_duration,
                                 args.event_timeout, args.poll, checkpoint, out_dir, previous)
        lab.cleanup(tuple(args.domains))
        print(f"\nCompleted. Results: {out_dir / 'trials_table.csv'}")
        # Evaluated over the FULL campaign (`previous`, which `--resume`
        # loaded plus whatever this invocation just ran), not just this
        # invocation's own newly-run cycles -- finding 6's resume fix
        # means a run that resumed into an already-fully-completed
        # campaign runs zero NEW cycles, and the exit code must still
        # reflect the whole campaign's real outcome, not "nothing failed
        # because nothing ran this time."
        rows = [r for r in previous
               if r.domain == "mobile" and r.scenario_mode == "repeatability"
               and r.iteration <= args.repeatability_cycles]
        # Minor fix: reflect failed cycles in the exit code -- this used
        # to always `return 0` even if every cycle came back INCOMPLETE/
        # ERROR, silently reporting a broken campaign as a success to
        # any script/CI checking $?.
        failed_cycles = [r for r in rows if r.status not in ("OK", "DRY_RUN")]
        if failed_cycles:
            return 2
        # 2nd review pass, finding 4: every cycle's own EVENTS completed
        # (status=="OK"), but a cycle whose recovery probe or mitigation-
        # withdrawal check came back False must not be reported as a
        # clean success either -- distinct exit code (3) from a real
        # failure (2), since the detect/mitigate pipeline itself did work.
        unconfirmed_recovery = [
            r for r in rows if r.traffic_recovered is False or r.mitigation_withdrawn is False
        ]
        if unconfirmed_recovery:
            print(
                f"WARNING: {len(unconfirmed_recovery)}/{len(rows)} cycle(s) completed detection/"
                "mitigation but recovery was not confirmed (traffic_recovered/mitigation_withdrawn "
                "== False) -- see trials_long.csv.",
                file=sys.stderr,
            )
            return 3
        return 0

    recovery_unconfirmed: list[TrialResult] = []
    for iteration in range(1, args.iterations + 1):
        jobs: list[tuple[str, tuple[str, ...]]] = []
        for vector in args.vectors:
            if vector == "MULTIDOMAIN_FLOOD":
                domains = tuple(args.domains)
                if len(domains) < 2:
                    print("Skipping MULTIDOMAIN_FLOOD: at least two domains are required", file=sys.stderr)
                    continue
                if all((iteration, d, vector, args.detection_mode, args.mode) in completed
                       for d in domains):
                    continue
                jobs.append((vector, domains))
            else:
                for domain in args.domains:
                    if (iteration, domain, vector, args.detection_mode, args.mode) not in completed:
                        jobs.append((vector, (domain,)))
        rng.shuffle(jobs)

        for vector, domains in jobs:
            print(f"\n=== iteration={iteration} vector={vector} domains={','.join(domains)} ===", flush=True)
            lab.healthcheck(domains)
            lab.cleanup(domains)
            lab.wait_for_baseline(domains)
            rows = run_trial(lab, iteration, vector, domains, args.attack_duration,
                             args.event_timeout, args.poll, scenario_mode=args.mode)
            append_checkpoint(checkpoint, rows)
            previous.extend(rows)
            write_outputs(out_dir, previous)
            # INVALID/INVALID_SCENARIO are expected, handled outcomes of
            # item 2's mobile preflight -- a known-flaky domain failing
            # its own pre-check is not a script bug, so it must NOT halt
            # the whole campaign the way a genuine ERROR/INCOMPLETE does.
            # They stay OUT of `completed` (only "OK" counts there), so
            # --resume retries them like any other not-yet-OK combination.
            invalid = [r for r in rows if r.status in ("INVALID", "INVALID_SCENARIO")]
            for r in invalid:
                print(f"  {r.status}: {r.domain}/{r.vector} -- {r.error}", file=sys.stderr)
            # NO_DETECTION (item 7 fix): a confirmed-attack/no-detection
            # row is a valid recorded outcome for an A/B sensitivity
            # comparison, not a script failure -- see extract_result()'s
            # own docstring for the detection/mitigation distinction that
            # keeps a REAL pipeline bug (detected but never mitigated)
            # still landing in `failed` below.
            no_detection = [r for r in rows if r.status == "NO_DETECTION"]
            for r in no_detection:
                print(f"  NO_DETECTION: {r.domain}/{r.vector} -- {r.error}", file=sys.stderr)
            failed = [r for r in rows if r.status not in
                     ("OK", "DRY_RUN", "INVALID", "INVALID_SCENARIO", "NO_DETECTION")]
            if failed:
                print("Trial incomplete; checkpoint saved. Fix the cause and rerun with --resume.", file=sys.stderr)
                return 2
            # 2nd review pass, finding 4: a row whose events all
            # completed (status=="OK") but whose recovery probe or
            # mitigation-withdrawal check came back False must still
            # surface -- tracked across the whole campaign so a
            # genuinely clean run (exit 0) can be told apart from one
            # that finished but left an unconfirmed recovery somewhere
            # (exit 3, distinct from a real failure's exit 2).
            unconfirmed = [r for r in rows if r.traffic_recovered is False or r.mitigation_withdrawn is False]
            for r in unconfirmed:
                print(f"  UNCONFIRMED RECOVERY: {r.domain}/{r.vector} -- "
                      f"traffic_recovered={r.traffic_recovered} mitigation_withdrawn={r.mitigation_withdrawn}",
                      file=sys.stderr)
            recovery_unconfirmed.extend(unconfirmed)
            time.sleep(args.cooldown)

    lab.cleanup(tuple(args.domains))
    lab.wait_for_baseline(args.domains)
    write_outputs(out_dir, previous)
    print(f"\nCompleted. Results: {out_dir / 'trials_table.csv'}")
    if recovery_unconfirmed:
        print(
            f"WARNING: {len(recovery_unconfirmed)} row(s) completed detection/mitigation but "
            "recovery was not confirmed (traffic_recovered/mitigation_withdrawn == False) -- "
            "see trials_long.csv.",
            file=sys.stderr,
        )
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
