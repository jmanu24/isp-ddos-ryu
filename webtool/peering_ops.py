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

Mirrors webtool/bng_ops.py's BngLifecycle shape (explicit start()/stop()
driven by webtool/orchestrator.py, not a menu loop), adapted for two
real subprocesses instead of one in-process session object.
"""
import subprocess
import time
from pathlib import Path
from typing import Optional

import config.settings as settings
from topologies.star_topology import (
    PEERING_UPLINK_ROOT_IP, PEERING_UPLINK_R1_IP,
    attach_peering_uplink_to_r1, detach_peering_uplink,
)

FLOW_LOG_PATH = "/tmp/webtool_peering_flow.log"
EXABGP_LOG_PATH = "/tmp/webtool_peering_exabgp.log"
EXABGP_CONF_PATH = "/tmp/webtool_peering_exabgp.conf"

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

    def stop(self) -> None:
        if self.exabgp_proc is not None:
            self.exabgp_proc.terminate()
            try:
                self.exabgp_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.exabgp_proc.kill()
            self.exabgp_proc = None

        if self.flow_proc is not None:
            self.flow_proc.terminate()
            try:
                self.flow_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.flow_proc.kill()
            self.flow_proc = None

        detach_peering_uplink()
