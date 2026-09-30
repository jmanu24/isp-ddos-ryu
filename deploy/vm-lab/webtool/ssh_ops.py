"""
webtool/ssh_ops.py -- thin sshpass-based SSH wrapper, same access pattern
already validated by hand for this lab (mobile-bringup-order memory):
`sshpass -p <pw> ssh -o StrictHostKeyChecking=no -o
UserKnownHostsFile=/dev/null <user>@<ip> <cmd>`. No paramiko dependency --
this repo's requirements.txt doesn't list it, and sshpass+openssh is
already a hard prerequisite of this lab (README's own `sudo apt install
sshpass`).
"""

import shlex
import subprocess
from typing import Optional

from webtool.inventory import NODES_BY_NAME, credentials_for

_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=5",
]


class SshResult:
    def __init__(self, rc: int, stdout: str, stderr: str):
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr

    @property
    def ok(self) -> bool:
        return self.rc == 0

    @property
    def reachable(self) -> bool:
        """True if the SSH transport itself worked, independent of the
        remote COMMAND's own exit status. ssh exits 255 for its own
        connection-level failures (refused, no route, timeout, auth);
        124/127 are this wrapper's own local timeout/exec failures. Any
        other code is the remote command's real exit status, which means
        the SSH session itself succeeded."""
        return self.rc not in (255, 124, 127)


def _target(node_name: str):
    node = NODES_BY_NAME.get(node_name)
    if node is None:
        raise KeyError(f"nodo desconocido: {node_name}")
    user, password = credentials_for(node_name)
    return node.ip, user, password


def run(node_name: str, command: str, timeout: int = 15, become: bool = False) -> SshResult:
    """Runs `command` on node_name over SSH and waits for completion."""
    ip, user, password = _target(node_name)
    remote_cmd = f"sudo -n {command}" if become and user != "root" else command
    argv = ["sshpass", "-p", password, "ssh", *_SSH_OPTS, f"{user}@{ip}", remote_cmd]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return SshResult(proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired:
        return SshResult(124, "", f"timeout tras {timeout}s")
    except FileNotFoundError as exc:
        return SshResult(127, "", str(exc))


def run_detached(node_name: str, command: str, log_path: str, become: bool = False) -> SshResult:
    """Launches `command` on node_name as a detached background process
    (setsid + nohup, matching the launch pattern already validated for
    srscu/srsdu -- see mobile-bringup-order memory) and returns
    immediately with the remote shell's own PID (last line of stdout).
    """
    remote = (
        f"rm -f {shlex.quote(log_path)} && "
        f"setsid nohup {command} > {shlex.quote(log_path)} 2>&1 < /dev/null & "
        f"echo $!"
    )
    return run(node_name, remote, timeout=10, become=become)


def kill_pid(node_name: str, pid: str, become: bool = False) -> SshResult:
    return run(node_name, f"kill -9 {shlex.quote(str(pid))} 2>/dev/null; true", timeout=10, become=become)


def tail_file(node_name: str, path: str, lines: int = 200) -> SshResult:
    return run(node_name, f"tail -n {int(lines)} {shlex.quote(path)} 2>&1", timeout=10)


def journalctl(node_name: str, unit: str, lines: int = 200) -> SshResult:
    return run(
        node_name,
        f"journalctl -u {shlex.quote(unit)} --no-pager -n {int(lines)} 2>&1",
        timeout=15, become=True,
    )


def docker_logs(node_name: str, container: str, lines: int = 200) -> SshResult:
    return run(
        node_name,
        f"docker logs --tail {int(lines)} {shlex.quote(container)} 2>&1",
        timeout=15, become=True,
    )
