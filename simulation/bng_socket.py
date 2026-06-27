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
    Holds ONE persistent connection, reused across calls, instead of
    reconnecting per call -- confirmed on a real run that reconnecting
    rapidly (bng_traffic_simulator.py's tick loop makes several calls
    per second) was the actual cause of a periodic, otherwise
    unexplained session DHCPRELEASE/re-establish cycle: the exact same
    config and session-traffic-start command, issued once by hand via
    bngblaster-cli and then left alone, ran 109s with "Flapped: 0" and
    0% loss, while this module's old "open a fresh connection every
    call" approach reliably reproduced the cycle within ~20s. Treat
    that as this old binary's control-socket implementation not
    tolerating connection churn well, not a framing requirement -- the
    underlying request/response exchange itself was always fine.
    """

    def __init__(self, sock_path: str):
        self.sock_path = sock_path
        self._sock: socket.socket = None

    def _connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(_RECV_TIMEOUT_S)
        s.connect(self.sock_path)
        self._sock = s

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _recv_response(self, s: socket.socket) -> dict:
        chunks = []
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                try:
                    return json.loads(b"".join(chunks).decode("utf-8"))
                except json.JSONDecodeError:
                    continue
        except socket.timeout:
            pass
        raw = b"".join(chunks).decode("utf-8", errors="replace")
        if not raw:
            raise RuntimeError(f"no response from {self.sock_path}")
        return json.loads(raw)

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

        Retries once over a fresh connection if the persistent one was
        closed/broken since the last call (e.g. bngblaster itself
        restarted) -- transparent to callers, who already handle
        OSError/RuntimeError from this method either way.
        """
        req = json.dumps({"command": command, "arguments": arguments or {}}).encode("utf-8")
        last_exc = None
        for attempt in (1, 2):
            if self._sock is None:
                self._connect()
            try:
                self._sock.sendall(req)
                resp = self._recv_response(self._sock)
                break
            except (OSError, json.JSONDecodeError) as exc:
                last_exc = exc
                self.close()
        else:
            raise RuntimeError(f"{command!r} failed after reconnect: {last_exc}")

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
