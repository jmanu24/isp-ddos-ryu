"""
webtool/peering_ops.py — BGP Peering domain process lifecycle for
webtool/orchestrator.py (docs/peering-plan.md §5).

Two modes, switched on settings.PEERING_DISTRIBUTED_MODE:

MININET MODE (default, the original design -- see docs/peering-plan.md
§5). Owns the two processes the domain needs, neither of which is the
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

DISTRIBUTED-VM MODE (deploy/vm-lab). Confirmed impossible to run the
above as-is across separate VMs: attach_peering_uplink_to_r1() moves a
veth into r1's own PID namespace via `ip link set ... netns <pid>`,
which has no cross-machine equivalent. Instead:

  - `flow` + `softflowd` run as persistent systemd services on the
    separate `br` VM (deploy/vm-lab/ansible/roles/br), installed and
    started by Ansible -- not spawned per-topology-start. start() only
    verifies they're active (via SSH); stop() leaves them running.
  - `exabgp` and `nfcapd` run as persistent systemd services on THIS
    host (deploy/vm-lab/ansible/roles/orchestrator) -- exabgp peers with
    br's real address (settings.PEERING_DIST_BR_IP) instead of a veth
    one; nfcapd listens for the NetFlow stream softflowd-peering (on br)
    exports directly to it, over the real network, instead of to a
    local nfcapd on br. start() only verifies both are active (locally,
    no SSH needed for either).
  - collectors/peering_flow_collector.py lists/decodes nfcapd's capture
    files with plain local os.listdir/subprocess now -- they land on
    THIS host's own disk, not br's (see that module's own docstring for
    why this moved off br entirely rather than staying an SSH read).

Mirrors webtool/bng_ops.py's BngLifecycle shape (explicit start()/stop()
driven by webtool/orchestrator.py, not a menu loop), adapted for four
real subprocesses instead of one in-process session object.
"""
import subprocess
import time
from pathlib import Path
from typing import Optional

from eventlet import tpool

import config.settings as settings

if not settings.PEERING_DISTRIBUTED_MODE:
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
# FIRST ATTEMPT at nfdump's documented floor (2) measured WORSE Td (41s,
# then 59s) than this 5s baseline (12-21s) -- but that measurement was
# taken under nfdump/nfcapd 1.6.18, which only names capture files down
# to MINUTE resolution regardless of -t. At rotate=2 that means up to 30
# rotations/minute all racing for the same filename, silently
# overwriting each other's data (confirmed via nfcapd's own internal
# rotation count not matching the number of surviving files on disk) --
# a real, separate bug from anything about eventlet or nfdump call
# volume, now fixed by upgrading to nfdump 1.7.4 (adds seconds to
# capture filenames below 60s, see deploy/install_bgp_peering.sh).
# Retrying rotate=2 now that this confound is gone -- if Td is still
# worse than 5s's baseline, the other standing hypothesis (ryu-manager
# runs under eventlet; a plain subprocess.run() nfdump call blocks the
# WHOLE process, not just one green thread, and more files means more
# blocking calls per unit of attack time) is next to investigate.
NFCAPD_ROTATE_SECONDS = 2

# Same AS numbers validated end-to-end in deploy/spike_flowspec_flow.sh
# (docs/peering-plan.md §2.2) -- kept identical here rather than
# introducing new untested values.
FLOW_LOCAL_AS = 65001
EXABGP_LOCAL_AS = 65002


def _ssh_br(args: list) -> subprocess.CompletedProcess:
    """
    Runs one command on the `br` VM over SSH (distributed mode only).
    BatchMode=yes -- fails fast with a clear error instead of hanging on
    an interactive password prompt if key-based auth isn't set up (see
    settings.PEERING_DIST_BR_SSH_USER's own comment).

    tpool.execute(), NOT a direct call -- if this webtool app's own
    Flask-SocketIO instance ends up on eventlet's async_mode (it
    auto-selects eventlet when available, and this venv has it for
    ryu-manager's sake), a blocking subprocess.run() here would freeze
    its whole reactor the same way it did ryu-manager's -- see
    telemetry/broadband_adapter.py's own _ssh() for the confirmed
    real-run failure and collectors/peering_flow_collector.py's _ssh_br
    for the same fix applied there.
    """
    return tpool.execute(
        subprocess.run,
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
         # accept-new, not the default (ask): the orchestrator role
         # already pre-seeds known_hosts via ssh-keyscan, but that task
         # tolerates failure (br might not be up yet on an early run) --
         # this is the fallback so a stale/missing entry doesn't hang
         # BatchMode's non-interactive session waiting on a prompt it can
         # never answer, without silently accepting a CHANGED key like
         # StrictHostKeyChecking=no would.
         "-o", "StrictHostKeyChecking=accept-new",
         f"{settings.PEERING_DIST_BR_SSH_USER}@{settings.PEERING_DIST_BR_SSH_HOST}",
         *args],
        capture_output=True, text=True, timeout=15,
    )


def _ensure_active_on_br(unit: str) -> None:
    """Distributed-mode equivalent of _ensure_alive() below -- these
    units are Ansible-managed systemd services on br, not processes this
    class spawns, so "ensure alive" means "ensure systemd already has it
    up", not "start it"."""
    result = _ssh_br(["systemctl", "is-active", unit])
    if result.stdout.strip() != "active":
        raise RuntimeError(
            f"{unit} is not active on br (deploy/vm-lab/ansible/roles/br) -- "
            f"systemctl is-active reported {result.stdout.strip()!r}. "
            f"Run the br playbook / check `systemctl status {unit}` on br."
        )


def _ensure_active_local(unit: str) -> None:
    """Local equivalent of _ensure_active_on_br() -- for services managed
    on THIS host (exabgp, in distributed mode -- see deploy/vm-lab/
    ansible/roles/orchestrator). No SSH needed, it's the same machine."""
    result = subprocess.run(
        ["systemctl", "is-active", unit], capture_output=True, text=True,
    )
    if result.stdout.strip() != "active":
        raise RuntimeError(
            f"{unit} is not active on this host (deploy/vm-lab/ansible/roles/"
            f"orchestrator) -- systemctl is-active reported {result.stdout.strip()!r}. "
            f"Check `systemctl status {unit}`."
        )


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


def _write_exabgp_conf(
    path: str, fifo_path: str, peer_ip: str, local_ip: str,
    connect_port: Optional[int] = None,
) -> None:
    """
    exabgp does NOT create or read PEERING_EXABGP_FIFO itself -- this
    `process` block runs `cat <fifo>`, whose stdout exabgp treats as
    commands (see mitigation/peering_backend.py's docstring and the
    ExaBGP wiki's "Controlling ExaBGP: using a named PIPE"). The FIFO
    itself must already exist before exabgp starts (see start() below).

    connect_port: distributed mode only -- flow<->exabgp can't use the
    standard BGP port 179 there (br's FRR already holds it system-wide,
    see settings.PEERING_DIST_FLOW_PORT's own comment). None (Mininet
    mode) omits the `connect` line entirely, so exabgp falls back to its
    own default of 179, matching flow's own `-b ...:179` there.
    """
    connect_line = f"    connect {connect_port};\n" if connect_port else ""
    conf = f"""process peering {{
    run /bin/cat {fifo_path};
    encoder text;
}}

neighbor {peer_ip} {{
    router-id {local_ip};
    local-address {local_ip};
    local-as {EXABGP_LOCAL_AS};
    peer-as {FLOW_LOCAL_AS};
{connect_line}
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
    (topologies/star_topology.py's attach_peering_uplink_to_r1) --
    MININET MODE. In DISTRIBUTED MODE (settings.PEERING_DISTRIBUTED_MODE)
    `flow`/softflowd/nfcapd are Ansible-managed systemd services on a
    separate `br` VM instead -- see this module's own docstring.
    """

    def __init__(self, r1=None):
        # r1 is a Mininet host object in Mininet mode, unused (pass None
        # or omit) in distributed mode -- kept as the same constructor
        # shape so webtool/orchestrator.py's call site doesn't need a
        # mode-specific branch of its own.
        self.r1 = r1
        self.flow_proc = None
        self.exabgp_proc = None
        self.softflowd_proc = None
        self.nfcapd_proc = None

    def start(self) -> None:
        if settings.PEERING_DISTRIBUTED_MODE:
            self._start_distributed()
        else:
            self._start_mininet()

    def stop(self) -> None:
        if settings.PEERING_DISTRIBUTED_MODE:
            self._stop_distributed()
        else:
            self._stop_mininet()

    # ------------------------------------------------------------------
    # Distributed-VM mode
    # ------------------------------------------------------------------

    def _start_distributed(self) -> None:
        # flow/softflowd (br) and exabgp/nfcapd (this host) are ALL
        # Ansible-managed systemd services now (deploy/vm-lab/ansible/
        # roles/br and .../orchestrator) -- this only verifies they're
        # active, it never starts/spawns anything. Fail loud here rather
        # than let a dead service surface later as an hours-later "why
        # does telemetry see nothing" mystery, same rationale as
        # _ensure_alive() below. exabgp used to be spawned per-topology-
        # start via subprocess.Popen (like Mininet mode still does) --
        # moved to a persistent service instead, since deploy/vm-lab's
        # config (peer/local addresses, connect port) never actually
        # changes between runs, unlike Mininet's veth addresses which
        # only exist once attach_peering_uplink_to_r1() creates them.
        #
        # nfcapd moved from br to here (orchestrator) -- softflowd-peering
        # exports its NetFlow stream directly to wherever the collector
        # runs now, instead of to a local nfcapd on br this process then
        # had to SSH+nfdump into. See collectors/peering_flow_collector.
        # py's own module docstring for the full reasoning; this is the
        # same "point the exporter at the collector" simplification.
        #
        # softflowd-peering, not plain softflowd -- deploy/vm-lab/ansible/
        # roles/br names it that deliberately, to avoid colliding with
        # Ubuntu's own softflowd apt package's default unit (which it
        # masks rather than configures).
        for unit in ("flow", "softflowd-peering"):
            _ensure_active_on_br(unit)
        _ensure_active_local("exabgp")
        _ensure_active_local("nfcapd")

    def _stop_distributed(self) -> None:
        # Nothing to do -- flow/softflowd (br) and exabgp/nfcapd (here)
        # are all persistent Ansible-managed systemd services, shared
        # across topology start/stop cycles, not per-session processes
        # this class owns in distributed mode.
        pass

    # ------------------------------------------------------------------
    # Mininet mode (original design)
    # ------------------------------------------------------------------

    def _start_mininet(self) -> None:
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
                 "-a", PEERING_UPLINK_ROOT_IP,
                 # ROOT CAUSE of the long-unresolved "traffic leak" finding
                 # (docs/peering-plan.md §6): without --hooked, `flow`
                 # creates its `inet flowspecs { chain flowspecs {...} }`
                 # as a REGULAR (non-base) nftables chain -- confirmed via
                 # a full, un-grepped `nft list ruleset` on the VM showing
                 # no `type filter hook ...; priority ...;` line on it at
                 # all. Per flow's own source
                 # (src/kernel/linux/mod.rs, KernelArgs::hooked's doc
                 # comment): "If not set, the nftables rule must be
                 # `jump`ed or `goto`ed from a base (hooked) chain in the
                 # same table to take effect." Nothing in this project ever
                 # added such a jump/goto, so the discard rule has existed
                 # in nftables (passing every earlier "rule present" check
                 # this project used) WITHOUT EVER BEING EVALUATED BY THE
                 # KERNEL, the entire time -- not an intermittent leak, no
                 # actual blocking effect at all. --hooked attaches it
                 # directly to nftables' own `input` hook (matches this
                 # project's own topology: central_server is a dummy
                 # interface local to r1, see topologies/star_topology.py's
                 # add_central_server(), so traffic to it is locally
                 # delivered -- the `input` hook, not `forward`, is the
                 # correct one and also flow's own --hooked default).
                 "--hooked"],
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
                # nfdump 1.7.x renamed the output-directory flag: 1.6.18's
                # `-w` (bare "sync writes" boolean) + `-l <dir>` became a
                # single `-w <dir>` (confirmed via `nfcapd -h` on the VM --
                # `-l` no longer appears in the 1.7.4 usage text at all).
                # The old two-flag form silently fails: -w now expects an
                # argument, so it swallows the following "-l" token as its
                # directory and errors "path does not exist: -l".
                ["nfcapd", "-w", settings.PEERING_NFCAPD_DIR,
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
                 # of cutting it. Left at maxlife=2 and no expint override
                 # -- the confirmed-best softflowd timeout settings
                 # measured at the time (against NFCAPD_ROTATE_SECONDS=5;
                 # kept unchanged for now while NFCAPD_ROTATE_SECONDS is
                 # retried at 2 with nfdump 1.7.4, to isolate that one
                 # variable -- see NFCAPD_ROTATE_SECONDS' own comment
                 # above for why the original rotate=2 measurement was
                 # confounded by a separate nfdump filename-collision
                 # bug). The actual architecture change that
                 # was needed instead landed in
                 # collectors/peering_flow_collector.py: it no longer
                 # waits for a subsequent rotation before trusting a
                 # file, it trusts any file nfcapd has stopped calling
                 # nfcapd.current.<pid> (nfcapd's own atomic-rename-on-
                 # close convention already guarantees that's complete).
                 "-t", "general=1", "-t", "maxlife=2"],
                stdout=softflowd_log, stderr=subprocess.STDOUT,
            )
        time.sleep(1)
        _ensure_alive(self.softflowd_proc, "softflowd", SOFTFLOWD_LOG_PATH)

    def _stop_mininet(self) -> None:
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
