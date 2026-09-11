"""
webtool/peering_ops.py — BGP Peering domain process lifecycle for
webtool/orchestrator.py (docs/peering-plan.md §5).

Owns the two processes the domain needs, neither of which is the
Ryu controller's own Python process:

  - `flow` (github.com/hack3ric/flow), started inside r1's own network
    namespace via Mininet's r1.popen() -- it's the process that actually
    installs BGP FlowSpec routes as real nftables rules on r1. See
    docs/peering-plan.md §2 for why this is `flow` and not FRR (FRR's
    own FlowSpec-to-dataplane bridge never installs the rule for real,
    a confirmed unresolved gap in FRR mainline -- FRRouting/frr#3160).
  - `exabgp`, started in the ROOT namespace (same process tree as this
    orchestrator and the Ryu controller) via a plain subprocess.Popen --
    it's the BGP speaker mitigation/peering_backend.py's FIFO writes
    ultimately reach. exabgp does not create its own command FIFO (see
    that module's docstring); this class creates it before exabgp starts.
  - `softflowd` + `nfcapd`, BOTH started inside r1's own namespace (like
    `flow`) via r1.popen() -- softflowd sniffs r1's external-facing
    interface (topologies/star_topology.py's EXTERNAL_PEER_IFACE_R1,
    the link to peer_ext) and exports NetFlow to nfcapd over r1's own
    loopback, entirely within r1's namespace so no cross-namespace UDP
    delivery is needed. nfcapd writes its rotated capture files to
    PEERING_NFCAPD_DIR (config/settings.py) on the shared filesystem --
    collectors/peering_flow_collector.py (root namespace) reads them
    from there via `nfdump`, same as this class's own file paths do.

Mirrors webtool/bng_ops.py's BngLifecycle shape (explicit start()/stop()
driven by webtool/orchestrator.py, not a menu loop), adapted for four
real subprocesses instead of one in-process session object.
"""
import subprocess
import time
from pathlib import Path
from typing import Optional

import config.settings as settings
from topologies.star_topology import (
    PEERING_UPLINK_ROOT_IP, PEERING_UPLINK_R1_IP, EXTERNAL_PEER_IFACE_R1,
    attach_peering_uplink_to_r1, detach_peering_uplink,
)

FLOW_LOG_PATH = "/tmp/webtool_peering_flow.log"
EXABGP_LOG_PATH = "/tmp/webtool_peering_exabgp.log"
EXABGP_CONF_PATH = "/tmp/webtool_peering_exabgp.conf"
SOFTFLOWD_LOG_PATH = "/tmp/webtool_peering_softflowd.log"
NFCAPD_LOG_PATH = "/tmp/webtool_peering_nfcapd.log"

# softflowd -> nfcapd export target -- both run inside r1's own
# namespace, so this is r1's own loopback, never reachable/relevant
# from the root namespace.
NFCAPD_PORT = 9995

# nfcapd's own default rotation interval is 300s -- far too slow given
# this project's sub-second detection cadence (COLLECT_INTERVAL, see
# config/settings.py); attack traffic wouldn't show up in a readable
# capture file for up to 5 minutes otherwise.
#
# REVERTED from nfcapd's documented floor (2) back to 5: lowering it
# was meant to shrink Td (attack start -> real detection), reasoning
# that Td is bounded below by how long until a file rotates and becomes
# readable. Measured the OPPOSITE on the VM -- Td got WORSE (41s, then
# 59s) after lowering this, not better, even with softflowd's own
# expint tightened too. softflowd's own nfcapd-reported packet counts
# stayed continuous and healthy throughout those runs (no capture-side
# starvation), which points elsewhere: ryu-manager runs under eventlet,
# and a plain subprocess.run() call (collectors/peering_flow_collector.py's
# own nfdump invocation) blocks the WHOLE process, not just one green
# thread, for its duration -- confirmed earlier this session while
# chasing an unrelated apparent "freeze". Cutting the rotation interval
# from 5s to 2s roughly triples how many files (and therefore blocking
# nfdump calls) collectors/peering_flow_collector.py's poll() needs per
# unit of attack time, which can delay the controller's own cycle --
# for every domain, not just bgp -- more than the faster rotation ever
# saved. Reverted pending a real fix (e.g. eventlet-friendly subprocess
# handling, or batching multiple files into fewer nfdump invocations)
# rather than trading file-count overhead for latency blindly.
NFCAPD_ROTATE_SECONDS = 5

# Same AS numbers validated end-to-end in deploy/spike_flowspec_flow.sh
# (docs/peering-plan.md §2.2) -- kept identical here rather than
# introducing new untested values.
FLOW_LOCAL_AS = 65001
EXABGP_LOCAL_AS = 65002


def _ensure_alive(proc: subprocess.Popen, name: str, log_path: str) -> None:
    """
    Catches a process that exited immediately (e.g. a rejected CLI flag)
    before it becomes an hours-later "why does telemetry see nothing"
    mystery -- r1.popen()/subprocess.Popen don't raise on their own for
    a non-zero exit, they just leave a dead process no caller checks.
    Confirmed real failure mode on the VM: softflowd -B (not supported
    by this VM's build) exited with "invalid option -- 'B'" and the
    validation script ran to completion regardless, reporting only the
    downstream symptom (no flow records) with no clue softflowd was
    never running at all.
    """
    if proc.poll() is not None:
        raise RuntimeError(
            f"{name} exited immediately (code {proc.returncode}) -- see {log_path}:\n"
            f"{Path(log_path).read_text()}"
        )


def _write_exabgp_conf(path: str, fifo_path: str, peer_ip: str, local_ip: str) -> None:
    """
    exabgp does NOT create or read PEERING_EXABGP_FIFO itself -- this
    `process` block runs `cat <fifo>`, whose stdout exabgp treats as
    commands (see mitigation/peering_backend.py's docstring and the
    ExaBGP wiki's "Controlling ExaBGP: using a named PIPE"). The FIFO
    itself must already exist before exabgp starts (see start() below).
    """
    conf = f"""process peering {{
    run /bin/cat {fifo_path};
    encoder text;
}}

neighbor {peer_ip} {{
    router-id {local_ip};
    local-address {local_ip};
    local-as {EXABGP_LOCAL_AS};
    peer-as {FLOW_LOCAL_AS};

    family {{
        ipv4 flow;
    }}

    api {{
        processes [ peering ];
    }}
}}
"""
    Path(path).write_text(conf)


class PeeringLifecycle:
    """
    Owns the `flow` (on r1) and `exabgp` (root namespace) processes for
    the BGP Peering domain, plus the veth uplink between them
    (topologies/star_topology.py's attach_peering_uplink_to_r1).
    """

    def __init__(self, r1):
        self.r1 = r1
        self.flow_proc = None
        self.exabgp_proc = None
        self.softflowd_proc = None
        self.nfcapd_proc = None

    def start(self) -> None:
        attach_peering_uplink_to_r1(self.r1)

        fifo_path = settings.PEERING_EXABGP_FIFO
        Path(fifo_path).parent.mkdir(parents=True, exist_ok=True)
        if not Path(fifo_path).exists():
            subprocess.run(["mkfifo", "-m", "666", fifo_path], check=True)

        # flow derives its control socket's filename deterministically
        # from its bind address:port (always the same PEERING_UPLINK_R1_IP
        # here), so a prior instance killed ungracefully (e.g. a bare
        # `pkill -9`, which never gives it the chance to clean up its own
        # socket) leaves a stale file that a fresh flow then refuses to
        # bind over ("Address already in use") -- confirmed on the VM.
        # Mininet only isolates the network namespace, not the mount
        # namespace, so /run/flow is the same host directory regardless
        # of r1.popen() vs. the root namespace, safe to clear from here.
        for stale_sock in Path("/run/flow").glob("*.sock"):
            stale_sock.unlink(missing_ok=True)

        # `flow` runs INSIDE r1's own namespace (r1.popen, not a plain
        # subprocess.Popen) so its nftables installation lands on r1's
        # own dataplane -- the same distinction that made the standalone
        # spike (deploy/spike_flowspec_flow.sh) work: flow and the
        # traffic it needs to filter must share a namespace.
        with open(FLOW_LOG_PATH, "wb") as flow_log:
            self.flow_proc = self.r1.popen(
                ["flow", "run",
                 "-b", f"{PEERING_UPLINK_R1_IP}:179",
                 "-l", str(FLOW_LOCAL_AS),
                 "-r", str(EXABGP_LOCAL_AS),
                 "-i", PEERING_UPLINK_R1_IP,
                 "-a", PEERING_UPLINK_ROOT_IP],
                stdout=flow_log, stderr=subprocess.STDOUT,
            )
        # Give flow a moment to bind before exabgp's first connection
        # attempt -- not strictly required (exabgp retries), but avoids
        # a guaranteed-failed first attempt every single start_topology().
        time.sleep(1)
        _ensure_alive(self.flow_proc, "flow", FLOW_LOG_PATH)

        _write_exabgp_conf(
            EXABGP_CONF_PATH, fifo_path,
            peer_ip=PEERING_UPLINK_R1_IP, local_ip=PEERING_UPLINK_ROOT_IP,
        )
        with open(EXABGP_LOG_PATH, "wb") as exabgp_log:
            self.exabgp_proc = subprocess.Popen(
                ["exabgp", EXABGP_CONF_PATH],
                stdout=exabgp_log, stderr=subprocess.STDOUT,
            )
        time.sleep(1)
        _ensure_alive(self.exabgp_proc, "exabgp", EXABGP_LOG_PATH)

        # nfcapd first -- it must already be listening before softflowd
        # sends its first export, otherwise those initial UDP datagrams
        # are just dropped (no retry/buffering on softflowd's side).
        Path(settings.PEERING_NFCAPD_DIR).mkdir(parents=True, exist_ok=True)
        with open(NFCAPD_LOG_PATH, "wb") as nfcapd_log:
            self.nfcapd_proc = self.r1.popen(
                ["nfcapd", "-w", "-l", settings.PEERING_NFCAPD_DIR,
                 "-p", str(NFCAPD_PORT), "-t", str(NFCAPD_ROTATE_SECONDS)],
                stdout=nfcapd_log, stderr=subprocess.STDOUT,
            )
        time.sleep(1)
        _ensure_alive(self.nfcapd_proc, "nfcapd", NFCAPD_LOG_PATH)

        with open(SOFTFLOWD_LOG_PATH, "wb") as softflowd_log:
            self.softflowd_proc = self.r1.popen(
                ["softflowd", "-d",
                 "-i", EXTERNAL_PEER_IFACE_R1,
                 "-n", f"127.0.0.1:{NFCAPD_PORT}",
                 # NetFlow v5, not v9/v10 -- simpler and has one fewer
                 # documented ICMP-export bug in some softflowd builds
                 # (redmine.pfsense.org/issues/10436) than v9/v10; nfdump
                 # emits the same CSV schema regardless of input version.
                 # NOT the actual fix for the "Flows: 0" issue below,
                 # which persisted under both v9 and v5.
                 "-v", "5",
                 # The real root cause (confirmed on the VM via
                 # `softflowctl statistics`: "Packets received by
                 # libpcap" > 0 but "Packets processed: 0" for a plain
                 # ping, independent of protocol/NetFlow version) is that
                 # softflowd's underlying libpcap capture on Linux only
                 # hands packets to userspace once a capture-ring block
                 # fills, with no time-based flush -- a handful of ping
                 # packets never does that. This VM's softflowd 1.0.0
                 # build has no -B/buffer-size flag to shrink the block
                 # (confirmed: "invalid option -- 'B'"), so the fix is on
                 # the traffic side instead: validate_peering.py drives a
                 # real hping3 flood, not a bare ping, which is enough
                 # volume to fill a block promptly -- and is what this
                 # pipeline exists to detect in the first place.
                 # softflowd doesn't export a flow record until it
                 # expires (default general timeout is much longer than
                 # this project's detection cadence) -- confirmed on the
                 # VM: nfcapd logged "Flows: 0" for a real ping burst
                 # that finished well before the default timeout could
                 # have fired. -t general=1 forces near-immediate export
                 # once a flow goes idle for 1s, matching
                 # NFCAPD_ROTATE_SECONDS' own reasoning.
                 #
                 # Tried and REVERTED: maxlife=1 (was 2) and an expint=1
                 # override (softflowd's separate "how often to scan the
                 # flow table" timeout, default 60s, distinct from
                 # general/maxlife). Hypothesis was that a 60s scan cycle
                 # dominated Td's spread (12-21s baseline) via random
                 # phase offset. Measured the OPPOSITE on the VM: adding
                 # expint=1 made Td worse both at NFCAPD_ROTATE_SECONDS=2
                 # (41s -> 59s) and back at =5 (still 32s, worse than the
                 # 12-21s baseline with no expint override at all) --
                 # forcing softflowd to scan every 1s instead of 60s
                 # plausibly competes with its own packet capture loop
                 # under a real high-volume flood, adding latency instead
                 # of cutting it. Left at maxlife=2 (matches
                 # NFCAPD_ROTATE_SECONDS=5 with margin) and no expint
                 # override -- the confirmed-best settings measured so
                 # far. Reducing Td further below this ~12-21s floor
                 # looks like it needs an actual architecture change (e.g.
                 # collectors/peering_flow_collector.py safely reading a
                 # still-open file via an mtime-staleness check instead
                 # of always skipping the last one), not more timeout
                 # tuning.
                 "-t", "general=1", "-t", "maxlife=2"],
                stdout=softflowd_log, stderr=subprocess.STDOUT,
            )
        time.sleep(1)
        _ensure_alive(self.softflowd_proc, "softflowd", SOFTFLOWD_LOG_PATH)

    def stop(self) -> None:
        for attr in ("softflowd_proc", "nfcapd_proc", "exabgp_proc", "flow_proc"):
            proc = getattr(self, attr)
            if proc is None:
                continue
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            setattr(self, attr, None)

        detach_peering_uplink()
