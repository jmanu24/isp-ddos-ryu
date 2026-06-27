"""
bng_socket.py — shared client for BNGBlaster's Unix-socket JSON-RPC
control API (https://rtbrick.github.io/bngblaster/api/index.html),
`{"command": ..., "arguments": {...}}` in, `{"status": ...}` out.

Used by both simulation/bng_traffic_simulator.py (telemetry polling +
starting/stopping the attack stream/icmp-client) and
telemetry/broadband_adapter.py (apply_mitigation() -- session-stop/
session-start on the SAME running bngblaster instance's socket, BNGBlaster's
own native per-session mitigation action, not NETCONF/ACL).

NOTE: command names below (session-streams, session-info, session-stop,
session-start, stream-start, stream-stop) come from BNGBlaster's public
docs/changelog, not from a real run -- this couldn't be exercised on
macOS (BNGBlaster needs Linux raw sockets; see bng_traffic_simulator.py's
module docstring). icmp-client-start/-stop are this module's own
assumption, by analogy with stream-start/-stop and session-start/-stop's
naming convention -- BNGBlaster's docs don't confirm an icmp-client
equivalent exists. Verify all of these against a real
`bngblaster-cli run.sock <cmd>` response on the Ubuntu VM before trusting
them in a real demo; every parser in this pipeline is deliberately
defensive (falls back to 0/empty rather than raising) so a wrong field
or command name degrades gracefully instead of crashing the pipeline.
"""

import json
import os
import socket
import time

_RECV_TIMEOUT_S = 2.0


class BngControlSocket:
    def __init__(self, sock_path: str):
        self.sock_path = sock_path

    def call(self, command: str, arguments: dict = None) -> dict:
        """Opens a fresh connection per call rather than holding one
        open -- simpler and avoids framing assumptions (the docs don't
        specify whether responses are newline-delimited or
        end-of-write/close terminated), at the cost of one extra
        connect() per call, negligible against a tick interval measured
        in whole seconds.

        Raises RuntimeError on a {"status": "error", ...} response
        instead of returning it -- confirmed on a real run that this
        matters: stream-start/stream-stop with a "stream-group-id"
        argument (this module's own earlier, wrong guess -- the real
        arguments are name/session-id/flow-id/etc, no group-id at all)
        returned a clean {"status": "error", "code": 400, "message":
        "invalid argument"} every single time, and every call site only
        ever checked for socket/JSON exceptions, never the response
        body's own status -- so the attack stream silently never
        started for an entire debugging session with zero visible
        errors anywhere. Every call site already has a try/except
        around ctrl.call() for connection failures, so raising here
        routes a bad command/argument through the exact same path
        instead of needing a second kind of check at every call site.
        """
        req = json.dumps({"command": command, "arguments": arguments or {}})
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(_RECV_TIMEOUT_S)
            s.connect(self.sock_path)
            s.sendall(req.encode("utf-8"))
            chunks = []
            resp = None
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    try:
                        resp = json.loads(b"".join(chunks).decode("utf-8"))
                        break
                    except json.JSONDecodeError:
                        continue
            except socket.timeout:
                pass
        if resp is None:
            raw = b"".join(chunks).decode("utf-8", errors="replace")
            if not raw:
                raise RuntimeError(f"no response from {self.sock_path} for command {command!r}")
            resp = json.loads(raw)
        if resp.get("status") == "error":
            raise RuntimeError(f"{command!r} {arguments!r} -> {resp.get('code')} {resp.get('message')}")
        return resp


def wait_for_socket(sock_path: str, timeout_s: float = 10.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if os.path.exists(sock_path):
            return
        time.sleep(0.2)
    raise TimeoutError(f"bngblaster control socket {sock_path} did not appear within {timeout_s}s")
