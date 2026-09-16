"""
bng_socket_cli.py — thin CLI wrapper over BngControlSocket, for the
distributed VM lab (deploy/vm-lab): telemetry/broadband_adapter.py's
distributed apply_mitigation() SSHes to `suscriptor` and runs this to
issue a real session-stop/session-start against BNGBlaster's local
control socket, since that socket (AF_UNIX) has no cross-machine
equivalent -- this script IS the machine it lives on.

Usage: python3 bng_socket_cli.py <command> [json-args] [--sock PATH]
Prints the raw JSON response to stdout on success; on failure, prints
"ERROR: <message>" to stderr and exits 1 -- BngControlSocket.call()
already raises RuntimeError on a {"status":"error",...} response (see
its own docstring for why), so this CLI doesn't need its own duplicate
status check.
"""

import argparse
import json
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))
from simulation.bng_socket import BngControlSocket  # noqa: E402

DEFAULT_SOCK_PATH = "/tmp/bng_run.sock"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command")
    p.add_argument("json_args", nargs="?", default="{}")
    p.add_argument("--sock", default=DEFAULT_SOCK_PATH)
    args = p.parse_args()

    try:
        arguments = json.loads(args.json_args)
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON args {args.json_args!r}: {exc}", file=sys.stderr)
        sys.exit(1)

    ctrl = BngControlSocket(args.sock)
    try:
        resp = ctrl.call(args.command, arguments)
    except (OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(resp))


if __name__ == "__main__":
    main()
