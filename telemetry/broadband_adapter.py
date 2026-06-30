import os
import subprocess
from typing import List

from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter
from simulation.bng_socket import BngControlSocket

DEFAULT_BNG_CSV_PATH = "/tmp/ddos_bng_events.csv"
DEFAULT_BNG_SOCK_PATH = "/tmp/bng_run.sock"
# Must match deploy/setup_bng_netns.sh's own DNSMASQ_CONF/
# DHCP_BLACKLIST_PATH constants.
DEFAULT_DNSMASQ_CONF_PATH = "/etc/dnsmasq.d/bng-access.conf"
DEFAULT_DHCP_BLACKLIST_PATH = "/tmp/bng_dhcp_blacklist.hosts"

# Must match simulation/bng_traffic_simulator.py's CSV_COLUMNS exactly.
_CSV_COLUMNS = [
    "timestamp", "session_id", "device_id", "src_ip", "mac", "dst_ip", "dst_port",
    "protocol", "pps", "bps", "sessions_established", "sessions_flapped",
]


class BroadbandAdapter(DomainAdapter):
    """
    Telemetry + mitigation adapter for the Fixed Broadband Domain
    (BNG / OLT, real BNGBlaster pipeline -- see simulation/
    bng_traffic_simulator.py and bng_config.py for how the real
    pipeline up to this adapter's input CSV is built and driven).

    Telemetry (collect()): tails the CSV simulation/bng_traffic_
    simulator.py produces. That script drives the real BNGBlaster
    binary (real PPPoE/IPoE sessions, real packets, counters polled per
    SESSION from its control socket -- BNGBlaster's own native unit of
    "one subscriber", not a synthetic aggregate) and writes one row per
    (session, tick) sample. BNGBlaster itself only runs on Linux (raw
    sockets, root/cap_net_raw) -- this adapter just tails whatever lands
    in the CSV, so it works the same whether that producer ran locally
    or (as it actually must) on the Ubuntu test VM. sessions_established/
    sessions_flapped are carried in the CSV for native-telemetry record
    completeness (BNGBlaster's own session-counters vocabulary) but
    TelemetryEvent has no field for them -- same "exists for offline
    analysis, not the live detection path" convention as mobile_adapter.
    py's --extended-kpms columns.

    Mitigation (apply_mitigation()): two BNGBlaster-native actions per
    block, not just one:
      1. "session-stop" -- drop the attacking subscriber session
         immediately (the original mitigation; "session-start" on
         unblock re-establishes it).
      2. MAC blacklist via dnsmasq's dhcp-hostsfile ("<mac>,ignore") --
         confirmed necessary on a real run: BNGBlaster periodically
         re-DHCPs a session on its own (an internal ~15s cycle observed
         independent of any block/unblock activity), which would
         silently undo a session-stop-only block the next time it
         happened to fire. Blacklisting the MAC at the DHCP server
         means BNGBlaster can retry as many times as it wants -- it
         never gets an IP back until the blacklist entry is removed on
         unblock. dnsmasq re-reads its dhcp-hostsfile on SIGHUP, which
         this sends via `sudo -n` (non-interactive -- fails fast and
         logs rather than hanging on a password prompt if passwordless
         sudo isn't configured for this user; same throwaway-local-
         simulation tradeoff as the control socket's own chmod 0666).

    Resolving which session-id/MAC to target uses the src_ip->(session_id,
    mac) mapping learned during collect() (BNGBlaster's session-info
    doesn't index by IP, so this adapter has to remember the reverse
    mapping itself).
    """

    domain_name = "broadband"

    def __init__(
        self,
        bng_host: str = None,
        csv_path: str = DEFAULT_BNG_CSV_PATH,
        sock_path: str = DEFAULT_BNG_SOCK_PATH,
        dnsmasq_conf_path: str = DEFAULT_DNSMASQ_CONF_PATH,
        dhcp_blacklist_path: str = DEFAULT_DHCP_BLACKLIST_PATH,
    ):
        self.bng_host = bng_host
        self.csv_path = csv_path
        self.sock_path = sock_path
        self.dnsmasq_conf_path = dnsmasq_conf_path
        self.dhcp_blacklist_path = dhcp_blacklist_path
        self._last_offset = 0
        # BngControlSocket opens its own fresh connection per call() --
        # this instance is reused purely to avoid re-constructing it
        # every apply_mitigation(), it holds no connection state itself.
        self._ctrl = BngControlSocket(self.sock_path)
        # src_ip -> (session_id, mac), learned from collect()'s own CSV
        # rows -- the only place this adapter ever sees that mapping
        # (BNGBlaster's session-stop/-start take a session-id and the
        # DHCP blacklist takes a MAC, but MitigationAction only carries
        # the IP DDoSDetectionEngine classified).
        self._session_by_ip = {}
        self._mac_by_ip = {}

    def is_connected(self) -> bool:
        return os.path.exists(self.csv_path) and os.path.exists(self.sock_path)

    def collect(self) -> List[TelemetryEvent]:
        if not os.path.exists(self.csv_path):
            return []

        with open(self.csv_path, "r", newline="") as f:
            f.seek(self._last_offset)
            lines = f.readlines()
            self._last_offset = f.tell()

        events = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith(_CSV_COLUMNS[0]):
                continue  # header (possibly re-written if the file was recreated)
            fields = line.split(",")
            if len(fields) != len(_CSV_COLUMNS):
                continue
            row = dict(zip(_CSV_COLUMNS, fields))
            try:
                self._session_by_ip[row["src_ip"]] = int(row["session_id"])
                if row["mac"]:
                    self._mac_by_ip[row["src_ip"]] = row["mac"]
                events.append(TelemetryEvent(
                    domain=self.domain_name,
                    device_id=row["device_id"],
                    src_ip=row["src_ip"],
                    dst_ip=row["dst_ip"],
                    dst_port=int(row["dst_port"]),
                    protocol=row["protocol"],
                    pps=float(row["pps"]),
                    bps=float(row["bps"]),
                    timestamp=float(row["timestamp"]),
                ))
            except (ValueError, KeyError):
                continue
        return events

    def _reload_dnsmasq(self) -> bool:
        """SIGHUPs dnsmasq so it re-reads dhcp-hostsfile -- finds the PID
        via pgrep (unprivileged) and signals it via `sudo -n` (fails
        immediately rather than blocking on a password prompt)."""
        try:
            pid_out = subprocess.run(
                ["pgrep", "-f", f"dnsmasq.*{self.dnsmasq_conf_path}"],
                capture_output=True, text=True, timeout=5,
            )
            pid = pid_out.stdout.strip().splitlines()[0] if pid_out.stdout.strip() else None
            if not pid:
                print("[BROADBAND] dnsmasq process not found, cannot reload DHCP blacklist")
                return False
            result = subprocess.run(
                ["sudo", "-n", "kill", "-HUP", pid],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                print(f"[BROADBAND] sudo -n kill -HUP {pid} failed: {result.stderr.strip()}")
                return False
            return True
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"[BROADBAND] dnsmasq reload failed: {exc}")
            return False

    def _set_mac_blacklisted(self, mac: str, blacklisted: bool) -> bool:
        """Adds/removes "<mac>,ignore" in dnsmasq's dhcp-hostsfile, then
        reloads dnsmasq. Best-effort -- a missing/unwritable blacklist
        file (e.g. deploy/setup_bng_netns.sh never ran) degrades to a
        logged no-op rather than raising, same convention as every
        other BNGBlaster-socket failure in this adapter."""
        try:
            lines = []
            if os.path.exists(self.dhcp_blacklist_path):
                with open(self.dhcp_blacklist_path, "r") as f:
                    lines = [ln.rstrip("\n") for ln in f if ln.strip()]
            entry = f"{mac},ignore"
            lines = [ln for ln in lines if not ln.startswith(f"{mac},")]
            if blacklisted:
                lines.append(entry)
            with open(self.dhcp_blacklist_path, "w") as f:
                f.write("\n".join(lines) + ("\n" if lines else ""))
        except OSError as exc:
            print(f"[BROADBAND] cannot update DHCP blacklist {self.dhcp_blacklist_path}: {exc}")
            return False
        return self._reload_dnsmasq()

    def apply_mitigation(self, action: MitigationAction) -> bool:
        session_id = self._session_by_ip.get(action.src_ip)
        if session_id is None:
            print(f"[BROADBAND] cannot resolve src_ip {action.src_ip!r} to a session-id, "
                  f"skipping {action.action}")
            return False

        is_block = action.action in ("block", "rate_limit")
        command = "session-stop" if is_block else "session-start"
        ok = True
        try:
            self._ctrl.call(command, {"session-id": session_id})
        except (OSError, RuntimeError) as exc:
            print(f"[BROADBAND] {command} session-id={session_id} failed: {exc}")
            ok = False

        mac = self._mac_by_ip.get(action.src_ip)
        if mac:
            if not self._set_mac_blacklisted(mac, blacklisted=is_block):
                ok = False
        else:
            print(f"[BROADBAND] no MAC known for src_ip {action.src_ip!r}, "
                  f"DHCP blacklist not updated (session-stop/-start still applied)")

        print(f"[BROADBAND] {command} session-id={session_id} (src_ip={action.src_ip}, "
              f"mac={mac}, attack_type={action.attack_type})")
        return ok
