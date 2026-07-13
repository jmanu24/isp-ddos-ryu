"""
bng_socket.py — shared client for BNGBlaster's Unix-socket JSON-RPC
control API (https://rtbrick.github.io/bngblaster/api/index.html),
`{"command": ..., "arguments": {...}}` in, `{"status": ...}` out.

Used by both simulation/bng_traffic_simulator.py (telemetry polling +
starting/stopping the attack stream/icmp-client) and
telemetry/broadband_adapter.py (apply_mitigation() -- session-stop/
session-start on the SAME running bngblaster instance's socket, BNGBlaster's
own native per-session mitigation action, not NETCONF/ACL).

NOTE: command names (session-streams, session-info, session-stop,
session-start, session-traffic-start/-stop) are confirmed against real
runs on the installed BNGBlaster 0.9.17 binary -- see bng_config.py's
module docstring for what's been validated and what hasn't yet
(icmp-client-start/-stop still aren't). Every parser in this pipeline
is deliberately defensive (falls back to 0/empty rather than raising)
so an unexpected field shape degrades gracefully instead of crashing
the pipeline.
"""

import json
import os
import socket
import time

_RECV_TIMEOUT_S = 2.0


class BngControlSocket:
    """
    Opens a FRESH connection per call, closed right after -- confirmed
    on a real run that BNGBlaster's control socket only answers ONE
    request per accepted connection: the first call() on a persistent
    connection got a real response, every subsequent call() on that
    SAME connection then timed out ("no response") forever, even though
    bngblaster itself kept running fine (its own milestone logs kept
    printing). A previous version of this module held one persistent
    connection open across calls to reduce reconnect overhead -- that
    was based on a theory (rapid reconnects causing a periodic session
    flap) later disproven by other evidence, and it broke the control
    socket outright once exercised across a full pipeline cycle instead
    of a handful of manual bngblaster-cli calls. Back to one connection
    per call, the originally-confirmed-working design.
    """

    def __init__(self, sock_path: str):
        self.sock_path = sock_path

    def close(self) -> None:
        """No persistent state to release -- kept as a no-op so
        existing callers (BngScenarioSession.stop(), BroadbandAdapter)
        that call ctrl.close() don't need to change."""
        pass

    def call(self, command: str, arguments: dict = None) -> dict:
        """
        Raises RuntimeError on a {"status": "error", ...} response
        instead of returning it -- confirmed on a real run that this
        matters: a wrong argument name returned a clean {"status":
        "error", "code": 400, "message": "invalid argument"} every
        single time, and every call site only ever checked for socket/
        JSON exceptions, never the response body's own status -- so a
        misconfigured command silently never took effect for an entire
        debugging session with zero visible errors anywhere. Every call
        site already has a try/except around ctrl.call() for connection
        failures, so raising here routes a bad command/argument through
        the exact same path instead of needing a second kind of check
        at every call site.
        """
        req = json.dumps({"command": command, "arguments": arguments or {}}).encode("utf-8")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(_RECV_TIMEOUT_S)
            s.connect(self.sock_path)
            s.sendall(req)
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
