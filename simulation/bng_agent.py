"""
bng_agent.py — persistent BNGBlaster control daemon for the distributed
VM lab (deploy/vm-lab), run on the `suscriptor` VM.

webtool/bng_ops.py's BngLifecycle already does exactly what's needed
(own one running BngScenarioSession, launch/tick/teardown) -- reused
here as-is rather than reimplemented, just driven by a FIFO instead of
direct in-process calls from webtool/orchestrator.py, since in
distributed mode that Flask process runs on `orchestrator`, a different
VM from wherever BNGBlaster's raw-socket access actually has to live.

Same "plain-text FIFO command channel, no framework" choice exabgp's
own --api pipe uses in this project (see deploy/vm-lab/ansible/roles/
orchestrator/templates/exabgp.service.j2) -- one command per line:

  baseline
  attack <scenario>
  stop
  stop_all

webtool/bng_ops.py's distributed BngLifecycle (config.settings.
BNG_DISTRIBUTED_MODE) SSHes in and appends one of these lines to this
FIFO; this process's own read loop drives the real local BngLifecycle
in response. A FIFO write from a NEW ssh session blocks until this
process is actively reading (has one reader), same read-loop-reopens-
the-FIFO pattern any single-reader FIFO daemon needs -- open() is
re-issued after each EOF (writer closed) so the NEXT writer's open()
doesn't hang forever.

Usage (see deploy/vm-lab/ansible/roles/suscriptor's systemd unit):
  sudo python3 simulation/bng_agent.py --target-ip 10.10.0.100 \\
      --access-interface ens160 --network-interface ens192 \\
      --network-ip 10.10.0.90/24 --network-gateway 10.10.0.254 \\
      --fifo /run/bng-agent/cmd
"""

import argparse
import os
import sys
import time
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))

from simulation.bng_config import SCENARIOS  # noqa: E402
from webtool.bng_ops import BngLifecycle  # noqa: E402


def _log(msg: str) -> None:
    print(f"[bng-agent] {msg}", flush=True)


def _handle_line(life: BngLifecycle, line: str) -> None:
    parts = line.strip().split(maxsplit=1)
    if not parts:
        return
    cmd = parts[0]
    arg = parts[1].strip() if len(parts) > 1 else None

    try:
        if cmd == "baseline":
            life.start_baseline()
            _log("baseline started")
        elif cmd == "attack":
            if arg not in SCENARIOS:
                _log(f"unknown scenario {arg!r}, expected one of {SCENARIOS}")
                return
            life.start_attack(arg)
            _log(f"attack started: {arg}")
        elif cmd == "stop":
            life.stop_attack()
            _log("attack stopped, back to baseline")
        elif cmd == "stop_all":
            life.stop_all()
            _log("stopped, no session running")
        else:
            _log(f"unknown command {cmd!r}")
    except (OSError, RuntimeError) as exc:
        _log(f"command {line!r} failed: {exc}")


def run(fifo_path: str, life: BngLifecycle, start_baseline: bool) -> None:
    if not os.path.exists(fifo_path):
        os.mkfifo(fifo_path, 0o666)

    if start_baseline:
        life.start_baseline()
        _log("baseline started (autostart)")

    _log(f"listening on {fifo_path}")
    try:
        while True:
            # Re-opened every iteration -- see module docstring. A FIFO
            # open() for reading blocks until a writer connects, and
            # readline() returns "" (EOF) once that writer closes, not
            # once the FIFO is "empty" -- so the loop must re-open after
            # every writer disconnects, or the SECOND ssh-driven write
            # would hang forever waiting for a reader that already gave
            # up.
            with open(fifo_path, "r") as f:
                for line in f:
                    if line.strip():
                        _handle_line(life, line)
    except KeyboardInterrupt:
        pass
    finally:
        life.stop_all()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target-ip", required=True, help="victim's real address (e.g. victim's MGMT IP)")
    p.add_argument("--access-interface", default="ens160")
    p.add_argument("--network-interface", default="ens192")
    p.add_argument("--network-ip", default="10.10.0.90/24")
    p.add_argument("--network-gateway", default="10.10.0.254")
    p.add_argument("--fifo", default="/run/bng-agent/cmd")
    p.add_argument("--no-baseline", action="store_true", help="don't autostart the low_and_slow baseline")
    args = p.parse_args()

    if sys.platform != "linux":
        print("ERROR: bngblaster requires Linux (raw sockets) -- run this on suscriptor, not here.",
              file=sys.stderr)
        sys.exit(1)

    life = BngLifecycle(
        target_ip=args.target_ip,
        access_interface=args.access_interface,
        network_interface=args.network_interface,
        network_ip=args.network_ip,
        network_gateway=args.network_gateway,
    )
    run(args.fifo, life, start_baseline=not args.no_baseline)


if __name__ == "__main__":
    main()
