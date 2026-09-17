"""
webtool/bng_ops.py — session-to-switch labeling + a BngScenarioSession
lifecycle wrapper for webtool/orchestrator.py.

One real bngblaster process serves the whole star topology (per the
user's own explicit choice: "Una sola instancia bngblaster, sesiones
repartidas por switch") -- session_switch_label() below is a pure UI
label, not real per-switch network separation; see
simulation/bng_traffic_simulator.py's BngScenarioSession._attack_cmd()
for why session-traffic-start/-stop can only toggle ALL sessions of the
one running process together.

DISTRIBUTED MODE (settings.BNG_DISTRIBUTED_MODE, deploy/vm-lab): in
Mininet mode this class owns a real BngScenarioSession directly (local
subprocess.Popen of the bngblaster binary). In distributed mode it
never touches BngScenarioSession at all -- start_baseline/start_attack/
stop_attack/stop_all instead SSH to the separate `suscriptor` VM and
append one command line to simulation/bng_subscriber_agent.py's FIFO
there (that script drives real per-subscriber PPPoE sessions against
accel-ppp on `bng`, plus real attack traffic -- see its own module
docstring; it replaces simulation/bng_agent.py's BNGBlaster
wrapper, see bngblaster_broadband_pipeline_status memory for why:
BNGBlaster's own sendto() succeeded but the frame was invisible to
every external observer on this lab, an unresolved bug). The FIFO
protocol (baseline/attack <scenario>/stop/stop_all) is unchanged from
the BNGBlaster-era agent, so THIS class's distributed-mode branch below
needed no code changes for that swap -- mirrors webtool/peering_ops.
py's _ssh_br pattern (BatchMode/accept-new/ConnectTimeout) for every
other cross-VM control call in this project.
"""

import subprocess
import threading

import config.settings as settings
from simulation.bng_traffic_simulator import BngScenarioSession

# bng_config.py's ONLY autostart=True scenario (8 sessions, low, steady
# rate) -- used as the standing broadband baseline, same way the mobile
# domain's GnbManager.start_benign_baseline and the enterprise domain's
# benign ICMP loop stand in for "normal" background traffic.
BASELINE_SCENARIO = "low_and_slow"


def session_switch_label(session_id: int, num_switches: int = 4) -> int:
    return ((session_id - 1) % num_switches) + 1


class BngLifecycle:
    """
    Owns one running BngScenarioSession plus its background tick thread,
    mirroring simulation/bng_interactive.py's own _run_tick_loop/
    _teardown_current pattern -- adapted to be driven by explicit start/
    stop calls from webtool/orchestrator.py instead of a menu loop.
    """

    def __init__(
        self,
        target_ip: str,
        tick_s: float = None,
        # Mininet-mode-only BngScenarioSession overrides -- unused in
        # distributed mode (see _ssh_write_fifo below, which never
        # constructs a BngScenarioSession at all). None means "let
        # BngScenarioSession use its own Mininet/netns defaults"
        # (veth-a/veth-n, 10.50.0.10/24), so every existing Mininet-mode
        # call site is unaffected by this widening.
        bng_host: str = None,
        access_interface: str = None,
        network_interface: str = None,
        network_ip: str = None,
        network_gateway: str = None,
    ):
        self.target_ip = target_ip
        self.tick_s = tick_s if tick_s is not None else settings.COLLECT_INTERVAL
        # Distributed mode never touches any of the local-session state
        # below (_lock/_stop_event/_thread/self.session) -- it's all
        # unused dead weight in that mode, kept only so this class's
        # shape stays identical between modes. simulation/
        # bng_subscriber_agent.py (running on suscriptor) is a separate,
        # self-contained script now -- it does NOT construct this class
        # at all (unlike the old BNGBlaster-era bng_agent.py, which
        # reused it for its real local launching), so there's no longer
        # an "agent's own process must never see this env var" hazard to
        # guard against here.
        self._distributed = settings.BNG_DISTRIBUTED_MODE
        self._session_kwargs = {
            k: v for k, v in {
                "bng_host": bng_host,
                "access_interface": access_interface,
                "network_interface": network_interface,
                "network_ip": network_ip,
                "network_gateway": network_gateway,
            }.items() if v is not None
        }
        self._lock = threading.Lock()
        self._stop_event = None
        self._thread = None
        self.session: BngScenarioSession = None

    def _tick_loop(self) -> None:
        while not self._stop_event.is_set():
            with self._lock:
                if self.session is not None:
                    try:
                        self.session.tick()
                    except (OSError, RuntimeError) as exc:
                        print(f"[webtool/bng_ops] tick failed: {exc}")
            self._stop_event.wait(self.tick_s)

    def _launch(self, scenario: str) -> None:
        """Caller must already hold self._lock."""
        self.session = BngScenarioSession(scenario=scenario, target_ip=self.target_ip, **self._session_kwargs)
        self.session.start()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._tick_loop, daemon=True)
        self._thread.start()

    def _teardown_current(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self.session is not None:
            self.session.stop()
        self.session, self._thread, self._stop_event = None, None, None

    def _ssh_write_fifo(self, line: str) -> None:
        """Distributed mode only: appends one command line to simulation/
        bng_subscriber_agent.py's FIFO on suscriptor -- see that
        module's own docstring for the tiny plain-text protocol
        (baseline/attack <scenario>/stop/stop_all). `echo ... > fifo`
        blocks until the agent's read loop has the FIFO open for
        reading, same as any single-reader
        FIFO -- its loop re-opens immediately after each line, so the
        window where no reader is attached is negligible in practice;
        ConnectTimeout/the outer timeout= below still bound the wait if
        the agent is down entirely, same posture as every other _ssh_*
        helper in this project (webtool/peering_ops.py's _ssh_br).
        """
        try:
            result = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                 "-o", "StrictHostKeyChecking=accept-new",
                 f"{settings.BNG_DIST_SUSCRIPTOR_SSH_USER}@{settings.BNG_DIST_SUSCRIPTOR_SSH_HOST}",
                 "sh", "-c", f"echo {line!r} > {settings.BNG_DIST_FIFO_PATH}"],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise RuntimeError(f"bng-agent FIFO write {line!r} failed: {exc}") from exc
        if result.returncode != 0:
            raise RuntimeError(f"bng-agent FIFO write {line!r} failed: {result.stderr.strip()}")

    def start_baseline(self) -> None:
        """low_and_slow autostarts its own attack traffic the moment the
        process comes up -- nothing else to do here."""
        if self._distributed:
            self._ssh_write_fifo("baseline")
            return
        self._teardown_current()
        with self._lock:
            self._launch(BASELINE_SCENARIO)

    def start_attack(self, scenario: str) -> None:
        """scenario == BASELINE_SCENARIO: the baseline is already
        running it -- just make sure its attack traffic is flowing (it
        always is, low_and_slow autostarts). Any OTHER scenario: tears
        down the current session and launches a fresh one for it, same
        as bng_interactive.py's 'cambiar'."""
        if self._distributed:
            self._ssh_write_fifo(f"attack {scenario}")
            return
        with self._lock:
            reuse_current = self.session is not None and self.session.scenario == scenario
            if reuse_current:
                if not self.session.attacking:
                    self.session.start_attack()
                return
        self._teardown_current()
        with self._lock:
            self._launch(scenario)
            if not self.session.attacking:
                self.session.start_attack()

    def stop_attack(self) -> None:
        """Stops attack traffic and falls back to the standing baseline
        -- broadband's benign traffic must never simply vanish, matching
        the always-on baselines the enterprise/mobile domains keep."""
        if self._distributed:
            self._ssh_write_fifo("stop")
            return
        with self._lock:
            on_baseline = self.session is not None and self.session.scenario == BASELINE_SCENARIO
            if on_baseline:
                if self.session.attacking:
                    self.session.stop_attack()
                return
        self._teardown_current()
        with self._lock:
            self._launch(BASELINE_SCENARIO)

    def stop_all(self) -> None:
        if self._distributed:
            self._ssh_write_fifo("stop_all")
            return
        self._teardown_current()
