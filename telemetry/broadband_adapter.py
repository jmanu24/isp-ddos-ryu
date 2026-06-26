import os
from typing import List

from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter
from simulation.bng_socket import BngControlSocket

DEFAULT_BNG_CSV_PATH = "/tmp/ddos_bng_events.csv"
DEFAULT_BNG_SOCK_PATH = "/tmp/bng_run.sock"

# Must match simulation/bng_traffic_simulator.py's _CSV_COLUMNS exactly.
_CSV_COLUMNS = [
    "timestamp", "session_id", "device_id", "src_ip", "dst_ip", "dst_port",
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

    Mitigation (apply_mitigation()): sends BNGBlaster's OWN native
    per-session control actions over the same control socket the
    simulator/poller used -- "session-stop" (drop the attacking
    subscriber session) for a block, "session-start" (re-establish it)
    for an unblock. This is BNGBlaster's real lifecycle action, not
    NETCONF/ACL -- there's no router/firewall behind this domain to
    push an ACL onto; BNGBlaster IS the simulated BNG, so stopping a
    session on it is the actual mitigation. Resolving which session-id
    to target uses the src_ip->session_id mapping learned during
    collect() (BNGBlaster's session-info doesn't index by IP, so this
    adapter has to remember the reverse mapping itself).
    """

    domain_name = "broadband"

    def __init__(
        self,
        bng_host: str = None,
        csv_path: str = DEFAULT_BNG_CSV_PATH,
        sock_path: str = DEFAULT_BNG_SOCK_PATH,
    ):
        self.bng_host = bng_host
        self.csv_path = csv_path
        self.sock_path = sock_path
        self._last_offset = 0
        # src_ip -> session_id, learned from collect()'s own CSV rows --
        # the only place this adapter ever sees that mapping (BNGBlaster's
        # session-stop/-start commands take a session-id, but
        # MitigationAction only carries the IP DDoSDetectionEngine
        # classified).
        self._session_by_ip = {}

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

    def apply_mitigation(self, action: MitigationAction) -> bool:
        session_id = self._session_by_ip.get(action.src_ip)
        if session_id is None:
            print(f"[BROADBAND] cannot resolve src_ip {action.src_ip!r} to a session-id, "
                  f"skipping {action.action}")
            return False

        command = "session-stop" if action.action in ("block", "rate_limit") else "session-start"
        try:
            ctrl = BngControlSocket(self.sock_path)
            ctrl.call(command, {"session-id": session_id})
        except (OSError, RuntimeError) as exc:
            print(f"[BROADBAND] {command} session-id={session_id} failed: {exc}")
            return False

        print(f"[BROADBAND] {command} session-id={session_id} (src_ip={action.src_ip}, "
              f"attack_type={action.attack_type})")
        return True
