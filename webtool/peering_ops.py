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
# capture file for up to 5 minutes otherwise. 5s (nfcapd's minimum
# supported interval is 2s, per its manpage) still batches enough flow
# records per file to be worth nfdump's per-file decode overhead in
# collectors/peering_flow_collector.py.
NFCAPD_ROTATE_SECONDS = 5

# Same AS numbers validated end-to-end in deploy/spike_flowspec_flow.sh
# (docs/peering-plan.md §2.2) -- kept identical here rather than
# introducing new untested values.
FLOW_LOCAL_AS = 65001
EXABGP_LOCAL_AS = 65002


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

        _write_exabgp_conf(
            EXABGP_CONF_PATH, fifo_path,
            peer_ip=PEERING_UPLINK_R1_IP, local_ip=PEERING_UPLINK_ROOT_IP,
        )
        with open(EXABGP_LOG_PATH, "wb") as exabgp_log:
            self.exabgp_proc = subprocess.Popen(
                ["exabgp", EXABGP_CONF_PATH],
                stdout=exabgp_log, stderr=subprocess.STDOUT,
            )

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

        with open(SOFTFLOWD_LOG_PATH, "wb") as softflowd_log:
            self.softflowd_proc = self.r1.popen(
                ["softflowd", "-d",
                 "-i", EXTERNAL_PEER_IFACE_R1,
                 "-n", f"127.0.0.1:{NFCAPD_PORT}",
                 # NetFlow v5, not v9/v10: softflowd 1.0.0 has a confirmed
                 # upstream bug where ICMP packets are silently dropped
                 # (0 processed despite libpcap receiving them) when
                 # exporting as v9/v10 -- reproduced on the VM via
                 # `softflowctl statistics` showing "Packets received by
                 # libpcap" > 0 but "Packets processed: 0" for a plain
                 # ping. v5 has no such issue (redmine.pfsense.org/issues
                 # /10436, forum.netgate.com/topic/172943) and nfdump's
                 # own CSV output schema is identical either way.
                 "-v", "5",
                 # softflowd (irino/softflowd) calls pcap_set_timeout(0)
                 # and never sets immediate mode -- on Linux this means
                 # its TPACKET_V3 capture ring only hands packets to
                 # userspace once a whole block fills, with no time-based
                 # flush. Confirmed on the VM via softflowctl statistics:
                 # "Packets received by libpcap" > 0 but "Packets
                 # processed: 0" for a handful of packets, regardless of
                 # protocol/NetFlow version -- pcap_dispatch() was simply
                 # never being called on such a small ring. A small -B
                 # buffer keeps the block size low enough that even
                 # modest bursts (see the hping3 flood in
                 # validate_peering.py, not a bare ping) fill and flush
                 # promptly; real DDoS flood volumes would do this
                 # regardless, but validation traffic needs the help.
                 "-B", "65536",
                 # softflowd doesn't export a flow record until it
                 # expires (default general timeout is much longer than
                 # this project's detection cadence) -- confirmed on the
                 # VM: nfcapd logged "Flows: 0" for a real ping burst
                 # that finished well before the default timeout could
                 # have fired. -t general=1 forces near-immediate export
                 # once a flow goes idle for 1s, matching
                 # NFCAPD_ROTATE_SECONDS' own reasoning.
                 "-t", "general=1", "-t", "maxlife=2"],
                stdout=softflowd_log, stderr=subprocess.STDOUT,
            )

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
