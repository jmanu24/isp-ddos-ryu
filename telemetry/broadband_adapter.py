import json
import logging
import os
import re
import shlex
import subprocess
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional

from eventlet import tpool

import config.settings as settings
from core.log_format import log_line
from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter
from simulation.bng_socket import BngControlSocket

DEFAULT_BNG_CSV_PATH = "/tmp/ddos_bng_events.csv"
DEFAULT_BNG_SOCK_PATH = "/tmp/bng_run.sock"
# Must match deploy/setup_bng_netns.sh's own DNSMASQ_CONF/
# DHCP_BLACKLIST_PATH constants.
DEFAULT_DNSMASQ_CONF_PATH = "/etc/dnsmasq.d/bng-access.conf"
DEFAULT_DHCP_BLACKLIST_PATH = "/tmp/bng_dhcp_blacklist.hosts"

_REPO_SCRIPT_DIR = "/opt/Tesis_Controller/simulation"
_SSH_TIMEOUT_S = 10

_NORMAL_DST_PORT = 80
_NORMAL_PROTOCOL = "TCP"


def _ssh(user: str, host: str, args: list, timeout: int = _SSH_TIMEOUT_S,
          input_text: str = None) -> subprocess.CompletedProcess:
    """Same BatchMode/accept-new convention as webtool/peering_ops.py's
    _ssh_br -- see that function's docstring.

    shlex.join(args), NOT *args -- confirmed on a real run: the ssh
    CLIENT itself concatenates every argument after user@host with a
    single plain space to build the command line it sends to the
    remote shell, with NO extra quoting of its own. Passing
    ["sudo", "-n", "sh", "-c", script] as separate argv elements (as
    this used to) works fine for a plain multi-word command, but the
    moment `script` itself contains shell metacharacters (quotes, `|`,
    `;`, `$(...)`  -- exactly what _read_radius_new_text()'s script
    needs), the remote shell parses ONLY script's first word as -c's
    actual argument and treats the rest as separate, unrelated words on
    the OUTER login shell's own command line -- broken syntax, or at
    best silently wrong behavior, with no error surfaced anywhere (this
    adapter's own collect()/apply_mitigation() degrade a failed SSH
    call to a quiet return, so this was invisible until traced by hand
    against a live run). shlex.join() re-quotes the whole args list
    into ONE shell-safe string first, so ssh's own space-joining (a
    no-op on a single already-complete argv element) can't split it
    apart again.

    tpool.execute(), NOT a direct call -- confirmed on a real run:
    ryu-manager's whole process is one eventlet-cooperative reactor
    (its own startup warning, "1 RLock(s) were not greened", is the
    tell), and subprocess.run() is a genuinely blocking OS-level call
    (fork/exec/waitpid) that eventlet's monkey-patching does not make
    cooperative the way it does plain sockets. A single slow/stuck SSH
    call (observed: minutes, once even ~6.5 hours behind a large nfdump
    backlog on a different domain) freezes the ENTIRE controller --
    every domain's collect()/detect()/mitigate(), not just this one's --
    since nothing yields back to the reactor until it returns.
    tpool.execute() runs the call in a real OS thread from eventlet's
    own thread pool instead, so the reactor keeps servicing every other
    greenthread while this blocks.

    ControlMaster/ControlPersist -- confirmed on a real run: a bare SSH
    call here costs ~0.5s just for the fresh TCP+key-exchange+auth
    handshake, every single time, since this runs on EVERY collect()
    cycle (COLLECT_INTERVAL, nominally 0.5s). That's the dominant cost
    behind this domain's real-world cycle time being ~6x its nominal
    interval, which directly inflates UNBLOCK_CONFIRM_CYCLES's wall-clock
    duration (orchestration/controller.py) -- measured ~5min for a
    recovery that should only need ~50s at the nominal interval. Reusing
    one multiplexed connection (opened once, kept warm for
    ControlPersist seconds) turns every subsequent call here into a
    single round-trip over an already-authenticated session -- tens of
    ms instead of ~0.5s. /run is root-writable and cleared on reboot,
    matching this socket's own lifetime (this process runs as root via
    systemd). %C is ssh's own hash of user/host/port -- keeps the path
    short and collision-free without hand-rolling one per call site."""
    return tpool.execute(
        subprocess.run,
        ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={min(timeout, 5)}",
         "-o", "StrictHostKeyChecking=accept-new",
         "-o", "ControlMaster=auto", "-o", "ControlPersist=600",
         "-o", "ControlPath=/run/ssh-mux-%C",
         f"{user}@{host}", shlex.join(args)],
        input=input_text, capture_output=True, text=True, timeout=timeout,
    )

# Must match simulation/bng_traffic_simulator.py's CSV_COLUMNS exactly
# (Mininet mode only -- distributed mode has no CSV at all, see below).
_CSV_COLUMNS = [
    "timestamp", "session_id", "device_id", "src_ip", "mac", "dst_ip", "dst_port",
    "protocol", "pps", "bps", "sessions_established", "sessions_flapped",
]


class BroadbandAdapter(DomainAdapter):
    """
    Telemetry + mitigation adapter for the Fixed Broadband Domain (BNG).

    Two entirely different real pipelines feed this adapter, selected by
    settings.BNG_DISTRIBUTED_MODE:

    MININET MODE (self._distributed=False): tails the CSV simulation/
    bng_traffic_simulator.py produces, driving the real BNGBlaster
    binary (real PPPoE/IPoE sessions, real packets, counters polled per
    SESSION from its control socket). Unchanged from before distributed
    mode existed -- see that module's own docstring.

    DISTRIBUTED MODE (deploy/vm-lab, self._distributed=True): REPLACES
    an earlier BNGBlaster-based distributed design (see
    bngblaster_broadband_pipeline_status memory: BNGBlaster's own
    sendto() succeeded but the frame was invisible to every external
    observer on this lab, an unresolved bug). `bng` now runs accel-ppp
    (a real open-source BRAS/BNG) fronted by FreeRADIUS -- telemetry
    comes from FreeRADIUS's own real accounting records (Acct-Input-
    Octets/-Packets per session, genuinely generated BNG-side), not a
    client-side control socket:

      - collect(): tails FreeRADIUS's `detail` accounting log on `bng`
        (one flat-text record per Accounting-Start/-Interim-Update/
        -Stop packet) over SSH, computing pps/bps as the delta between
        consecutive records for the same Acct-Session-Id divided by the
        elapsed time between them -- REAL rate data, straight from the
        BNG's own AAA backend. RADIUS accounting has no L4 (protocol/
        port) visibility at all (a volumetric total, not a flow
        breakdown) -- that piece is merged in from suscriptor's own
        active_scenario.json (simulation/bng_subscriber_agent.py writes
        it: src_ip -> {protocol, dst_port} for whichever subscribers it
        is currently attacking), same "the synthetic producer already
        knows what it's simulating" convention this project already
        uses elsewhere (simulation/ul_traffic_simulator.py, and the old
        BNGBlaster-era CSV before it).
      - apply_mitigation(): two real BNG-native actions per block:
          1. `accel-cmd terminate ip <src_ip>` on `bng` -- drops the
             session immediately, accel-ppp's own real management
             interface (arguably MORE authentic than BNGBlaster's own
             session-stop, which just twiddled an internal socket
             command; this is the same tool a real BRAS operator uses).
             NOT "terminate username <mac>" -- confirmed on a real run:
             under IPoE every subscriber shares the same username
             (accel-ppp's own ifname fallback), so that could never
             match a specific one; `ip` needs no MAC lookup either.
          2. A per-MAC `Auth-Type := Reject` entry in FreeRADIUS's
             `users` file, then a FreeRADIUS restart -- needed for the
             SAME reason BNGBlaster's DHCP-blacklist was: accel-ppp
             retries auth on its own the next time the client re-DHCPs,
             so a terminate-only block would get silently undone the
             moment that happens. Blocking at the AAA layer means it
             can retry as many times as it wants -- it never gets
             re-admitted until the Reject entry is removed on unblock.
             This match is by MAC (Calling-Station-Id), not User-Name
             (which every IPoE subscriber shares) -- roles/bng's own
             tasks set FreeRADIUS's `files` module `key` directive to
             `%{Calling-Station-Id}` specifically so this matches.
          On unblock specifically, a third step: tells suscriptor's own
          bng_subscriber_agent.py (over the same FIFO webtool/bng_ops.py
          drives) to "kick" that subscriber into a fresh session
          immediately, rather than leaving it to notice on its own
          (potentially a long time later) that its old, terminate()'d
          session is a ghost -- see _kick_subscriber()'s own docstring
          and Subscriber.force_refresh() on the suscriptor side.

    Confirmed against a real run (2026-09-17): 8 real IPoE sessions,
    real DHCP leases, real per-subscriber source-based routing (see
    simulation/bng_subscriber_agent.py's own module docstring for why
    that routing override is needed at all), and real attack traffic
    correctly moving a session's own ipoeN RX counters, plus a full
    real detect -> block (accel-cmd terminate + FreeRADIUS reject) ->
    unblock -> kick cycle.

    Use self._logger, NOT print(), anywhere in this class -- confirmed
    on a real run: ryu-manager's systemd unit redirects stdout to a
    file (StandardOutput=append:/var/log/ryu-manager.log), and Python
    fully-buffers stdout when it isn't a TTY. A plain print() call can
    sit in that buffer indefinitely and never actually reach the file,
    while `self._logger.warning(...)` (a real logging.StreamHandler)
    flushes per record. This made several real bugs in this class look
    unfixable for a long stretch of debugging: the fix code was
    correct and running, but its own confirming print() output was
    silently never appearing in the log at all.
    """

    domain_name = "broadband"

    def __init__(
        self,
        bng_host: str = None,
        csv_path: str = None,
        sock_path: str = None,
        dnsmasq_conf_path: str = None,
        dhcp_blacklist_path: str = None,
        freeradius_detail_dir: str = None,
        accel_cmd_port: int = None,
        freeradius_users_path: str = None,
        logger: Optional[logging.Logger] = None,
    ):
        self._distributed = settings.BNG_DISTRIBUTED_MODE
        # Mininet-mode-only fields -- kept exactly as before, unused in
        # distributed mode (which reaches `bng`/`suscriptor` via
        # settings.BNG_DIST_BNG_SSH_HOST/BNG_DIST_SUSCRIPTOR_SSH_HOST
        # directly, see _ssh_bng/_ssh_suscriptor below).
        self.bng_host = bng_host or "bng-blaster-1"
        self.csv_path = csv_path or DEFAULT_BNG_CSV_PATH
        self.sock_path = sock_path or DEFAULT_BNG_SOCK_PATH
        self.dnsmasq_conf_path = dnsmasq_conf_path or DEFAULT_DNSMASQ_CONF_PATH
        self.dhcp_blacklist_path = dhcp_blacklist_path or DEFAULT_DHCP_BLACKLIST_PATH

        # Distributed-mode-only fields.
        self.freeradius_detail_dir = freeradius_detail_dir or settings.BNG_DIST_FREERADIUS_DETAIL_DIR
        self.accel_cmd_port = accel_cmd_port or settings.BNG_DIST_ACCEL_CMD_PORT
        self.freeradius_users_path = freeradius_users_path or settings.BNG_DIST_FREERADIUS_USERS_PATH
        self.target_ip = settings.BNG_DIST_TARGET_IP

        # Passed down from the Ryu app (its own self.logger), same
        # convention telemetry/mobile_adapter.py already uses -- defaults
        # to a plain logging.Logger so this stays usable standalone.
        self._logger = logger or logging.getLogger(__name__)
        # Tracks the last-logged connection state so collect() logs a
        # "telemetry source connected/lost" event only on the transition,
        # same as MobileNetworkAdapter.collect()'s own SOURCE_CONNECTED/
        # SOURCE_LOST handling.
        self._was_connected = False
        self._last_offset = 0
        # BngControlSocket opens its own fresh connection per call() --
        # this instance is reused purely to avoid re-constructing it
        # every apply_mitigation(), it holds no connection state itself.
        # Mininet mode only -- distributed mode never touches it.
        self._ctrl = BngControlSocket(self.sock_path)

        # Distributed-mode telemetry parsing state.
        self._radius_detail_file = None
        self._radius_offset = 0
        self._radius_buffer = ""
        # Acct-Session-Id -> (octets, packets, time) at the last record
        # seen for that session -- collect() computes pps/bps as the
        # delta since this, then updates it.
        self._radius_last: Dict[str, tuple] = {}
        # src_ip -> Acct-Session-Id / MAC (User-Name, since accel-ppp's
        # ipoe module authenticates by Calling-Station-Id), learned from
        # collect()'s own FreeRADIUS records -- the only place this
        # adapter ever sees that mapping (MitigationAction only carries
        # the IP DDoSDetectionEngine classified).
        self._session_by_ip: Dict[str, str] = {}
        self._mac_by_ip: Dict[str, str] = {}

        if self._distributed:
            # Every new controller process starts with a clean
            # mitigation slate -- same reasoning as the old BNGBlaster-
            # era _clear_dhcp_blacklist (see its own comment, kept below
            # for Mininet mode): a Reject entry left over from a
            # previous process's block is by definition orphaned.
            self._clear_radius_rejects()
        else:
            self._clear_dhcp_blacklist()

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def is_connected(self) -> bool:
        if self._distributed:
            result = self._ssh_bng(["systemctl", "is-active", "--quiet", "accel-pppd", "freeradius"])
            return result.returncode == 0
        return os.path.exists(self.csv_path) and os.path.exists(self.sock_path)

    def _ssh_suscriptor(self, args: list, input_text: str = None) -> subprocess.CompletedProcess:
        return _ssh(settings.BNG_DIST_SUSCRIPTOR_SSH_USER, settings.BNG_DIST_SUSCRIPTOR_SSH_HOST, args,
                    input_text=input_text)

    def _ssh_bng(self, args: list, input_text: str = None) -> subprocess.CompletedProcess:
        return _ssh(settings.BNG_DIST_BNG_SSH_USER, settings.BNG_DIST_BNG_SSH_HOST, args, input_text=input_text)

    # ------------------------------------------------------------------
    # Telemetry -- distributed mode (FreeRADIUS accounting on `bng`)
    # ------------------------------------------------------------------

    _RADIUS_SPLIT = "---BNG_RADIUS_SPLIT---"

    def _read_radius_new_text(self) -> tuple:
        """(connected, new_text) -- finds the newest detail-* file under
        freeradius_detail_dir (it rotates daily, see settings.py's own
        BNG_DIST_FREERADIUS_DETAIL_DIR comment), tails it from the last
        byte offset. Resets the offset (and re-fetches once) if the
        filename changed since the last poll -- either a day rollover,
        or freeradius/the directory not existing yet.

        sudo -n wraps the whole script -- confirmed on a real run: the
        radacct directory tree is 0700 freerad:freerad (FreeRADIUS's own
        default), unreadable by BNG_DIST_BNG_SSH_USER (labadmin)
        otherwise. -n fails fast rather than hanging on a password
        prompt if passwordless sudo isn't configured for this user, same
        posture as every other sudo -n use in this project."""
        script = (
            f'f=$(ls -t {self.freeradius_detail_dir}/detail-* 2>/dev/null | head -1); '
            f'if [ -z "$f" ]; then echo MISSING; exit 0; fi; '
            f'echo "$f"; echo "{self._RADIUS_SPLIT}"; '
            f'stat -c%s "$f"; echo "{self._RADIUS_SPLIT}"; '
            f'tail -c +$(({self._radius_offset} + 1)) "$f"'
        )
        try:
            result = self._ssh_bng(["sudo", "-n", "sh", "-c", script])
        except (subprocess.TimeoutExpired, OSError) as exc:
            self._logger.error(log_line("broadband", "TELEMETRY", "ERROR", f"ssh to bng failed: {exc}"))
            return False, ""

        out = result.stdout
        if result.returncode != 0 or out.strip() == "MISSING" or self._RADIUS_SPLIT not in out:
            return False, ""

        filename_part, _, rest = out.partition(self._RADIUS_SPLIT)
        size_part, _, content = rest.partition(self._RADIUS_SPLIT)
        filename = filename_part.strip()
        try:
            size = int(size_part.strip())
        except ValueError:
            return False, ""

        if filename != self._radius_detail_file:
            self._radius_detail_file = filename
            self._radius_offset = 0
            self._radius_buffer = ""
            return self._read_radius_new_text()

        if size < self._radius_offset:
            self._radius_offset = 0
            self._radius_buffer = ""
            return self._read_radius_new_text()

        new_text = content[1:] if content.startswith("\n") else content
        self._radius_offset = size
        return True, new_text

    @staticmethod
    def _parse_radius_record(block: str) -> dict:
        """One `key = value` dict per detail-file record -- the first
        (untabbed) line is a human-readable timestamp header, every
        other line is `\tKey = Value` (quotes stripped)."""
        fields = {}
        for line in block.splitlines():
            line = line.strip()
            if not line or " = " not in line:
                continue
            key, _, value = line.partition(" = ")
            fields[key.strip()] = value.strip().strip('"')
        return fields

    def _read_active_scenario(self) -> dict:
        """src_ip -> {protocol, dst_port}, from suscriptor's own state
        (simulation/bng_subscriber_agent.py) -- see this class's own
        docstring for why RADIUS accounting alone can't supply
        protocol/dst_port.

        Plain HTTP GET, not SSH+cat -- this state changes only on
        attack start/stop, so paying a fresh SSH handshake (~0.5s,
        confirmed on a real run) on every collect() cycle to read the
        same unchanged bytes was pure overhead. Not wrapped in
        tpool.execute() the way this class's SSH calls are -- eventlet's
        monkey-patching (applied by ryu-manager's own startup, before
        this module ever imports) already makes plain socket I/O
        cooperative; the tpool workaround exists specifically because
        subprocess.run()'s fork/exec/waitpid ISN'T covered by that
        patching, which doesn't apply here at all."""
        url = f"http://{settings.BNG_DIST_SUSCRIPTOR_IP}:{settings.BNG_DIST_SUSCRIPTOR_HTTP_PORT}/active_scenario"
        try:
            with urllib.request.urlopen(url, timeout=_SSH_TIMEOUT_S) as resp:
                body = resp.read()
            if not body.strip():
                return {}
            return json.loads(body)
        except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
            return {}

    def _collect_distributed(self) -> List[TelemetryEvent]:
        connected, new_text = self._read_radius_new_text()

        if connected and not self._was_connected:
            self._logger.info(log_line("broadband", "TELEMETRY", "SOURCE_CONNECTED",
                                        f"path={self.freeradius_detail_dir}"))
        elif not connected and self._was_connected:
            self._logger.warning(log_line("broadband", "TELEMETRY", "SOURCE_LOST",
                                           f"path={self.freeradius_detail_dir}"))
        self._was_connected = connected

        if not connected:
            return []

        self._radius_buffer += new_text
        # Records are blank-line separated -- the LAST split segment may
        # be a partial record still being written to, keep it buffered
        # for next time rather than parsing it early.
        blocks = self._radius_buffer.split("\n\n")
        self._radius_buffer = blocks.pop() if blocks else ""

        active_scenario = self._read_active_scenario()
        now = time.time()
        # One event per session per collect() call, not per record --
        # same reasoning as the Mininet-mode path's own dedup (see
        # collect()'s docstring there): each record is a cumulative
        # counter, not a rate to sum, and a large backlog (e.g. right
        # after this adapter reconnects) would otherwise hand the
        # correlator a burst of stale samples all at once.
        latest_by_session: Dict[str, TelemetryEvent] = {}
        for block in blocks:
            if not block.strip():
                continue
            fields = self._parse_radius_record(block)
            session_id = fields.get("Acct-Session-Id")
            src_ip = fields.get("Framed-IP-Address")
            if not session_id or not src_ip:
                continue
            mac = fields.get("Calling-Station-Id") or fields.get("User-Name")
            if mac:
                self._mac_by_ip[src_ip] = mac
            self._session_by_ip[src_ip] = session_id

            try:
                octets = float(fields.get("Acct-Input-Octets", 0))
                packets = float(fields.get("Acct-Input-Packets", 0))
            except ValueError:
                continue
            record_time = now
            ts_field = fields.get("Timestamp")
            if ts_field:
                try:
                    record_time = float(ts_field)
                except ValueError:
                    pass

            prev = self._radius_last.get(session_id)
            self._radius_last[session_id] = (octets, packets, record_time)
            if prev is None:
                continue  # first record for this session -- no delta yet
            prev_octets, prev_packets, prev_time = prev
            dt = record_time - prev_time
            if dt <= 0:
                continue
            bps = max(0.0, (octets - prev_octets) * 8.0 / dt)
            pps = max(0.0, (packets - prev_packets) / dt)
            if pps <= 0.0 and bps <= 0.0:
                continue

            meta = active_scenario.get(src_ip, {})
            latest_by_session[session_id] = TelemetryEvent(
                domain=self.domain_name,
                device_id="bng",
                src_ip=src_ip,
                dst_ip=self.target_ip,
                dst_port=int(meta.get("dst_port", _NORMAL_DST_PORT) or _NORMAL_DST_PORT),
                protocol=meta.get("protocol", _NORMAL_PROTOCOL),
                pps=pps,
                bps=bps,
                timestamp=record_time,
            )
        return list(latest_by_session.values())

    # ------------------------------------------------------------------
    # Telemetry -- Mininet mode (BNGBlaster CSV, unchanged)
    # ------------------------------------------------------------------

    def _read_new_lines_local(self) -> tuple:
        """(connected, lines) -- Mininet-mode local-file path, unchanged
        behavior from before distributed mode existed."""
        connected = os.path.exists(self.csv_path)
        if not connected:
            return False, []

        # simulation/bng_traffic_simulator.py's BngScenarioSession.start()
        # deletes and recreates this CSV on every launch (its own
        # documented, intentional behavior -- avoids replaying a dead
        # process's stale rows). A long-lived controller process that
        # outlives more than one BngScenarioSession (e.g. webtool/
        # bng_ops.py's BngLifecycle switching scenarios mid-run) keeps
        # this same DomainAdapter instance across that switch, so
        # self._last_offset still points into the OLD, now-deleted
        # file. Confirmed on a real run: seeking past a freshly
        # recreated (much shorter) file's end just returns zero lines
        # forever, never catching back up -- collect() silently stops
        # reporting any broadband telemetry the moment a second
        # BngScenarioSession replaces the first. Detect that case by
        # comparing the file's current size against the stored offset
        # and rewind to 0 when it shrank.
        if os.path.getsize(self.csv_path) < self._last_offset:
            self._last_offset = 0

        with open(self.csv_path, "r", newline="") as f:
            f.seek(self._last_offset)
            lines = f.readlines()
            self._last_offset = f.tell()
        return True, lines

    def _collect_local(self) -> List[TelemetryEvent]:
        connected, lines = self._read_new_lines_local()

        if connected and not self._was_connected:
            self._logger.info(log_line("broadband", "TELEMETRY", "SOURCE_CONNECTED", f"path={self.csv_path}"))
        elif not connected and self._was_connected:
            self._logger.warning(log_line("broadband", "TELEMETRY", "SOURCE_LOST", f"path={self.csv_path}"))
        self._was_connected = connected

        if not connected:
            return []

        # One event per session per collect() call, not per CSV row --
        # same reasoning/fix as telemetry/mobile_adapter.py's own
        # latest-sample-per-IMSI dedup (see its collect() docstring):
        # each row is a RATE sample (pps/bps at that tick), not a byte
        # count to sum, and MultidomainCorrelator sums every event in a
        # dst_ip bucket assuming they're concurrent flows. Reading a
        # large backlog in one collect() call -- e.g. right after this
        # adapter is (re)constructed against an already-long-running
        # BngScenarioSession's CSV, as happens whenever the controller
        # restarts without the BNG process itself restarting -- would
        # otherwise hand the correlator hundreds of stale samples from
        # 8 real sessions all at once, which reads as a sudden burst
        # from 8 distinct sources and falsely triggers a distributed-
        # flood block against every real session. Confirmed on a real
        # run: a controller restart against a ~16-minute-old standing
        # low_and_slow baseline immediately session-stopped all 8 BNG
        # sessions this way.
        latest_by_session: Dict[int, TelemetryEvent] = {}
        for line in lines:
            line = line.strip()
            if not line or line.startswith(_CSV_COLUMNS[0]):
                continue  # header (possibly re-written if the file was recreated)
            fields = line.split(",")
            if len(fields) != len(_CSV_COLUMNS):
                continue
            row = dict(zip(_CSV_COLUMNS, fields))
            try:
                session_id = int(row["session_id"])
                self._session_by_ip[row["src_ip"]] = session_id
                if row["mac"]:
                    self._mac_by_ip[row["src_ip"]] = row["mac"]
                latest_by_session[session_id] = TelemetryEvent(
                    domain=self.domain_name,
                    device_id=row["device_id"],
                    src_ip=row["src_ip"],
                    dst_ip=row["dst_ip"],
                    dst_port=int(row["dst_port"]),
                    protocol=row["protocol"],
                    pps=float(row["pps"]),
                    bps=float(row["bps"]),
                    timestamp=float(row["timestamp"]),
                )
            except (ValueError, KeyError):
                continue
        return list(latest_by_session.values())

    def collect(self) -> List[TelemetryEvent]:
        return self._collect_distributed() if self._distributed else self._collect_local()

    # ------------------------------------------------------------------
    # Mitigation -- distributed mode (accel-cmd + FreeRADIUS reject list)
    # ------------------------------------------------------------------

    def _accel_cmd(self, args: list) -> subprocess.CompletedProcess:
        return self._ssh_bng(["accel-cmd", "-p", str(self.accel_cmd_port), *args])

    def _read_users_lines(self) -> list:
        # sudo -n -- /etc/freeradius/3.0/ is root:freerad, mode 640
        # (Ubuntu's stock freeradius package), unreadable by
        # BNG_DIST_BNG_SSH_USER (labadmin) otherwise.
        result = self._ssh_bng(["sudo", "-n", "sh", "-c", f"cat {self.freeradius_users_path} 2>/dev/null || true"])
        return result.stdout.splitlines()

    def _write_users_lines(self, lines: list) -> None:
        content = "\n".join(lines) + ("\n" if lines else "")
        result = self._ssh_bng(["sudo", "-n", "tee", self.freeradius_users_path], input_text=content)
        if result.returncode != 0:
            raise OSError(f"writing {self.freeradius_users_path} on bng failed: {result.stderr.strip()}")

    def _reload_freeradius(self) -> bool:
        # restart, not a config-reload signal -- FreeRADIUS's `users`
        # file (an authorize-time flat file, unlike dnsmasq's dhcp-
        # hostsfile) isn't guaranteed to be picked up by a lighter
        # reload across every FreeRADIUS packaging, and a lab-scale
        # restart's brief interruption to in-flight auth/accounting is
        # an acceptable tradeoff here (same "throwaway local-simulation"
        # posture as every other mitigation shortcut in this project).
        try:
            result = self._ssh_bng(["sudo", "-n", "systemctl", "restart", "freeradius"])
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._logger.warning(f"[BROADBAND] freeradius restart failed: {exc}")
            return False
        if result.returncode != 0:
            self._logger.warning(f"[BROADBAND] freeradius restart failed: {result.stderr.strip()}")
            return False
        return True

    _REJECT_LINE_RE = re.compile(r"^(\S+)\s+Auth-Type\s*:=\s*Reject\s*$")

    def _set_mac_rejected(self, mac: str, rejected: bool) -> bool:
        """Inserts/removes a `<mac> Auth-Type := Reject` line in
        FreeRADIUS's `users` file. Matches by MAC because roles/bng's
        own tasks set the `files` module's `key` directive to
        `%{Calling-Station-Id}` -- the accept-all posture lives in
        sites-available/default's authorize{} unlang instead of a
        `users`-file DEFAULT line (see roles/bng's own tasks comment),
        so there's no DEFAULT line to insert above here anymore; a
        per-MAC entry just needs to exist somewhere for `files` to find
        it, order doesn't matter without one. Best-effort, same
        convention as every other mitigation-file failure in this
        adapter: a missing/unwritable users file degrades to a logged
        no-op."""
        try:
            lines = self._read_users_lines()
            lines = [ln for ln in lines if not self._REJECT_LINE_RE.match(ln.strip())
                     or self._REJECT_LINE_RE.match(ln.strip()).group(1) != mac]
            if rejected:
                lines.append(f"{mac} Auth-Type := Reject")
            self._write_users_lines(lines)
        except OSError as exc:
            self._logger.warning(f"[BROADBAND] cannot update FreeRADIUS users file {self.freeradius_users_path}: {exc}")
            return False
        return self._reload_freeradius()

    def _clear_radius_rejects(self) -> None:
        """Every new controller process starts with a clean mitigation
        slate -- a Reject entry left over from a PREVIOUS process's
        block (e.g. the controller restarted before that block's
        wall-clock duration elapsed) is orphaned, same reasoning as the
        old BNGBlaster-era DHCP blacklist clear-on-init."""
        try:
            lines = self._read_users_lines()
            cleaned = [ln for ln in lines if not self._REJECT_LINE_RE.match(ln.strip())]
            if cleaned != lines:
                self._write_users_lines(cleaned)
                self._reload_freeradius()
        except OSError as exc:
            self._logger.warning(f"[BROADBAND] cannot clear FreeRADIUS reject list {self.freeradius_users_path}: {exc}")

    def _apply_mitigation_distributed(self, action: MitigationAction) -> bool:
        is_block = action.action in ("block", "rate_limit")
        ok = True

        # NOT "terminate username <mac>" -- confirmed on a real run:
        # under IPoE every subscriber shares the SAME username (accel-
        # ppp's own ifname fallback, see accel-ppp.conf.j2's [ipoe]
        # comment), so a username-keyed terminate can never match a
        # specific subscriber. "terminate ip <address>" (accel-cmd's own
        # documented match key, confirmed via `accel-cmd help`) needs no
        # MAC lookup at all -- src_ip is already on the MitigationAction.
        if is_block:
            try:
                result = self._accel_cmd(["terminate", "ip", action.src_ip])
                if result.returncode != 0:
                    self._logger.warning(f"[BROADBAND] accel-cmd terminate ip={action.src_ip} failed: {result.stderr.strip()}")
                    ok = False
            except (OSError, subprocess.TimeoutExpired) as exc:
                self._logger.warning(f"[BROADBAND] accel-cmd terminate ip={action.src_ip} failed: {exc}")
                ok = False

        # The persistent FreeRADIUS reject (below) still needs the real
        # MAC -- terminate alone doesn't stop accel-ppp's own automatic
        # re-DHCP retry, and IP is not a stable identity across a fresh
        # lease the way Calling-Station-Id is.
        mac = self._mac_by_ip.get(action.src_ip)
        if mac is None:
            self._logger.warning(f"[BROADBAND] cannot resolve src_ip {action.src_ip!r} to a subscriber MAC, "
                  f"session terminated but no persistent reject entry added")
            return False

        if not self._set_mac_rejected(mac, rejected=is_block):
            ok = False

        if not is_block:
            self._kick_subscriber(action.src_ip)

        self._logger.warning(f"[BROADBAND] {'block' if is_block else 'unblock'} mac={mac} "
              f"(src_ip={action.src_ip}, attack_type={action.attack_type})")
        return ok

    def _kick_subscriber(self, src_ip: str) -> None:
        """Tells suscriptor's bng_subscriber_agent.py to fully
        re-establish the session at this IP -- see that module's own
        Subscriber.force_refresh() docstring for why this is needed at
        all: the accel-cmd terminate above (issued back when this
        subscriber was blocked) leaves that daemon's own cached self.ip
        pointing at a session `bng` no longer tracks, and nothing there
        would otherwise notice until its own next DHCP lease renewal --
        which could be a long time away. Best-effort: a failed kick
        just means that subscriber stays a silent ghost a bit longer,
        not a broken unblock (the FreeRADIUS reject is already gone by
        this point either way)."""
        self._logger.warning(f"[BROADBAND] kicking suscriptor for src_ip={src_ip}")
        try:
            result = self._ssh_suscriptor(["sh", "-c", f"echo 'kick {src_ip}' > {settings.BNG_DIST_FIFO_PATH}"])
            self._logger.warning(f"[BROADBAND] kick ssh rc={result.returncode} stderr={result.stderr.strip()!r}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._logger.warning(f"[BROADBAND] cannot kick suscriptor for src_ip={src_ip}: {exc}")

    # ------------------------------------------------------------------
    # Mitigation -- Mininet mode (BNGBlaster socket + dnsmasq, unchanged)
    # ------------------------------------------------------------------

    def _call_socket(self, command: str, arguments: dict) -> dict:
        return self._ctrl.call(command, arguments)

    def _reload_dnsmasq(self) -> bool:
        """SIGHUPs dnsmasq so it re-reads dhcp-hostsfile -- finds the PID
        via pgrep (unprivileged) and signals it via `sudo -n` (fails
        immediately rather than blocking on a password prompt).

        Anchored with ^dnsmasq -- deploy/setup_bng_netns.sh launches it
        as `sudo dnsmasq --conf-file=... --no-daemon`, and sudo's own
        monitor process keeps that full command line (including
        "dnsmasq" and the conf path) as ITS cmdline too, so an
        unanchored `dnsmasq.*<path>` pattern matches both processes.
        Confirmed on a real run: pgrep returned sudo's PID first (lower,
        since it started first) and every reload was silently sent to
        sudo instead of the actual dnsmasq -- sudo doesn't reliably
        forward SIGHUP to its child, so the dhcp-hostsfile was never
        actually re-read, no matter how many times block/unblock
        rewrote the file underneath it. Anchoring to "the command line
        starts with dnsmasq" excludes sudo's own ("...starts with sudo
        dnsmasq...") while still matching on the real conf-file path.
        """
        pgrep_args = ["pgrep", "-f", f"^dnsmasq .*{self.dnsmasq_conf_path}"]
        kill_args = ["sudo", "-n", "kill", "-HUP"]
        try:
            pid_out = subprocess.run(pgrep_args, capture_output=True, text=True, timeout=5)
            pid = pid_out.stdout.strip().splitlines()[0] if pid_out.stdout.strip() else None
            if not pid:
                print("[BROADBAND] dnsmasq process not found, cannot reload DHCP blacklist")
                return False
            result = subprocess.run([*kill_args, pid], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                self._logger.warning(f"[BROADBAND] sudo -n kill -HUP {pid} failed: {result.stderr.strip()}")
                return False
            return True
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._logger.warning(f"[BROADBAND] dnsmasq reload failed: {exc}")
            return False

    def _read_blacklist_lines(self) -> list:
        if not os.path.exists(self.dhcp_blacklist_path):
            return []
        with open(self.dhcp_blacklist_path, "r") as f:
            return [ln.rstrip("\n") for ln in f if ln.strip()]

    def _write_blacklist_lines(self, lines: list) -> None:
        content = "\n".join(lines) + ("\n" if lines else "")
        with open(self.dhcp_blacklist_path, "w") as f:
            f.write(content)

    def _clear_dhcp_blacklist(self) -> None:
        """Best-effort, same posture as every other BNGBlaster-adjacent
        failure here: a missing blacklist file (deploy/setup_bng_netns.sh
        never ran yet) or a dnsmasq that isn't up yet are both silent
        no-ops, not errors -- this only matters once a topology/dnsmasq
        actually exists."""
        try:
            if self._read_blacklist_lines():
                self._write_blacklist_lines([])
                self._reload_dnsmasq()
        except OSError as exc:
            self._logger.warning(f"[BROADBAND] cannot clear DHCP blacklist {self.dhcp_blacklist_path}: {exc}")

    def _set_mac_blacklisted(self, mac: str, blacklisted: bool) -> bool:
        """Adds/removes "<mac>,ignore" in dnsmasq's dhcp-hostsfile, then
        reloads dnsmasq. Best-effort -- a missing/unwritable blacklist
        file degrades to a logged no-op rather than raising, same
        convention as every other BNGBlaster-socket failure here."""
        try:
            lines = self._read_blacklist_lines()
            entry = f"{mac},ignore"
            lines = [ln for ln in lines if not ln.startswith(f"{mac},")]
            if blacklisted:
                lines.append(entry)
            self._write_blacklist_lines(lines)
        except OSError as exc:
            self._logger.warning(f"[BROADBAND] cannot update DHCP blacklist {self.dhcp_blacklist_path}: {exc}")
            return False
        return self._reload_dnsmasq()

    def _apply_mitigation_local(self, action: MitigationAction) -> bool:
        session_id = self._session_by_ip.get(action.src_ip)
        if session_id is None:
            self._logger.warning(f"[BROADBAND] cannot resolve src_ip {action.src_ip!r} to a session-id, "
                  f"skipping {action.action}")
            return False

        is_block = action.action in ("block", "rate_limit")
        command = "session-stop" if is_block else "session-start"
        ok = True
        try:
            self._call_socket(command, {"session-id": session_id})
        except (OSError, RuntimeError) as exc:
            self._logger.warning(f"[BROADBAND] {command} session-id={session_id} failed: {exc}")
            ok = False

        mac = self._mac_by_ip.get(action.src_ip)
        if mac:
            if not self._set_mac_blacklisted(mac, blacklisted=is_block):
                ok = False
        else:
            self._logger.warning(f"[BROADBAND] no MAC known for src_ip {action.src_ip!r}, "
                  f"DHCP blacklist not updated (session-stop/-start still applied)")

        self._logger.warning(f"[BROADBAND] {command} session-id={session_id} (src_ip={action.src_ip}, "
              f"mac={mac}, attack_type={action.attack_type})")
        return ok

    def apply_mitigation(self, action: MitigationAction) -> bool:
        return self._apply_mitigation_distributed(action) if self._distributed else self._apply_mitigation_local(action)
