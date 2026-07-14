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
"""

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

    def __init__(self, target_ip: str, tick_s: float = None):
        self.target_ip = target_ip
        self.tick_s = tick_s if tick_s is not None else settings.COLLECT_INTERVAL
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
        self.session = BngScenarioSession(scenario=scenario, target_ip=self.target_ip)
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

    def start_baseline(self) -> None:
        """low_and_slow autostarts its own attack traffic the moment the
        process comes up -- nothing else to do here."""
        self._teardown_current()
        with self._lock:
            self._launch(BASELINE_SCENARIO)

    def start_attack(self, scenario: str) -> None:
        """scenario == BASELINE_SCENARIO: the baseline is already
        running it -- just make sure its attack traffic is flowing (it
        always is, low_and_slow autostarts). Any OTHER scenario: tears
        down the current session and launches a fresh one for it, same
        as bng_interactive.py's 'cambiar'."""
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
        self._teardown_current()
