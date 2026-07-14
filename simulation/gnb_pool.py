#!/usr/bin/env python3
"""
gnb_pool.py — O-RAN multidomain DDoS proposal, star topology.

Real-traffic mobile UE generator anchored to topologies/star_topology.py's
per-switch gNB model: one real Mininet host per switch (gnb_<i>) acts as
a base station with its own gNB ID, and every simulated UE "behind" it
is a spoofed-source hping3 process launched FROM that specific physical
host -- unlike simulation/ue_traffic_generator.py's --interactive pool,
which round-robins UEs across a shared, undifferentiated host pool with
no fixed gNB identity per host.

Deliberately reuses ue_traffic_generator.py's validated internals
(hping3 command construction, the benign on/off loop, real process
lifecycle, the RC-command-queue mitigation protocol) rather than
reimplementing any of them -- those are exactly the fragile,
empirically-confirmed pieces this module must not risk diverging from.
The only genuinely new logic here is the per-gNB UE pool bookkeeping
(GnbManager) that anchors UEs to a fixed host instead of an interactive
free/occupied pool.

Not a standalone CLI -- driven by webtool/orchestrator.py against a
live star topology's gNB hosts.
"""

import threading
from dataclasses import dataclass
from typing import Dict, List, Optional
from uuid import uuid4

import subprocess

from simulation.ue_traffic_generator import (
    UeSpec,
    _hping3_argv,
    _benign_loop_argv,
    _RuntimeState,
    _terminate,
    _read_new_commands,
    _write_ue_ip_map,
    _write_ue_state,
    DEFAULT_CSV_PATH,
    DEFAULT_RC_COMMAND_QUEUE_PATH,
    DEFAULT_UE_IP_MAP_PATH,
    DEFAULT_UE_STATE_PATH,
    _TEST_MCC,
    _TEST_MNC,
)


def gnb_id_for(switch_index: int) -> str:
    return f"{_TEST_MCC}{_TEST_MNC}-{switch_index}"


@dataclass
class GnbAttack:
    attack_id: str
    imsis: List[int]
    domain: str = "mobile"


class GnbManager:
    """
    Owns the real per-gNB UE process pool for one running star topology.

    host_map: {switch_index: Mininet Host} for the gnb_<i> hosts (e.g.
    {1: <gnb_1 Host>, ..., 4: <gnb_4 Host>}), as returned by
    topologies/star_topology.py's build_topology() (hosts[i]["mobile_gnb"]).
    """

    def __init__(
        self,
        host_map: Dict[int, object],
        csv_path: str = DEFAULT_CSV_PATH,
        rc_queue_path: str = DEFAULT_RC_COMMAND_QUEUE_PATH,
        ue_ip_map_path=DEFAULT_UE_IP_MAP_PATH,
        ue_state_path: str = DEFAULT_UE_STATE_PATH,
    ):
        self._host_map = host_map
        self.csv_path = csv_path
        self.rc_queue_path = rc_queue_path
        self.ue_ip_map_path = ue_ip_map_path
        self.ue_state_path = ue_state_path

        self._lock = threading.Lock()
        self._state = _RuntimeState()
        # imsi -> UeSpec, covers both the always-on benign baseline UEs
        # and any currently-attacking ones.
        self._pool: Dict[int, UeSpec] = {}
        self._attacks: Dict[str, GnbAttack] = {}
        # Per-switch counter for the next UE index within that gNB's
        # 10.60.<i>.0/24 -- .2 is reserved for the benign baseline UE,
        # so this starts at 3.
        self._next_ue_index: Dict[int, int] = {i: 3 for i in host_map}

        self._rc_offset = 0
        self._stop_event = threading.Event()
        self._rc_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Benign baseline
    # ------------------------------------------------------------------

    def start_benign_baseline(self, target_ip: str) -> None:
        """One always-on benign UE per gNB (imsi=i*100+2, ip=10.60.<i>.2),
        an ICMP on/off loop (_benign_loop_argv) targeting `target_ip` --
        the star topology's central server. Never touched by
        start_attack/stop_attack -- a fixed, permanent part of the pool."""
        with self._lock:
            for i, host in self._host_map.items():
                imsi = i * 100 + 2
                ue = UeSpec(
                    imsi=imsi, ip=f"10.60.{i}.2", physical_host=f"gnb_{i}",
                    gnb_id=gnb_id_for(i), target_ip=target_ip, protocol="ICMP",
                    benign=True, benign_target_ip=target_ip,
                )
                self._pool[imsi] = ue
                self._state.procs[imsi] = host.popen(
                    _benign_loop_argv(ue), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            self._flush_ue_files()

    # ------------------------------------------------------------------
    # Attacks
    # ------------------------------------------------------------------

    def start_attack(
        self,
        switch_indices: List[int],
        count_per_gnb: int,
        protocol: str,
        dst_port: int,
        target_ip: str,
        rate_flags: List[str],
        low_slow: bool = False,
    ) -> str:
        """Allocates count_per_gnb fresh spoofed UEs per requested
        switch's gNB, launches a real hping3 process for each (via
        _hping3_argv, anchored to that gNB's own physical host), and
        returns an attack_id the caller tracks for stop_attack()/a
        duration-based auto-stop timer."""
        attack_id = str(uuid4())
        imsis: List[int] = []

        with self._lock:
            for i in switch_indices:
                host = self._host_map[i]
                for _ in range(count_per_gnb):
                    ue_index = self._next_ue_index[i]
                    self._next_ue_index[i] += 1
                    imsi = i * 100 + ue_index

                    ue = UeSpec(
                        imsi=imsi, ip=f"10.60.{i}.{ue_index}", physical_host=f"gnb_{i}",
                        gnb_id=gnb_id_for(i), target_ip=target_ip, protocol=protocol,
                        dst_port=dst_port, low_slow=low_slow, benign=False,
                        rate_flags=list(rate_flags),
                    )
                    self._pool[imsi] = ue
                    self._state.procs[imsi] = host.popen(
                        _hping3_argv(ue), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    imsis.append(imsi)

            self._attacks[attack_id] = GnbAttack(attack_id=attack_id, imsis=imsis)
            self._flush_ue_files()

        return attack_id

    def stop_attack(self, attack_id: str) -> bool:
        """Terminates every UE process this attack started and removes
        them from the pool entirely (no revert-to-benign -- attack-only
        UEs have no prior benign identity to revert to, unlike the
        interactive CLI's fixed pool)."""
        with self._lock:
            attack = self._attacks.pop(attack_id, None)
            if attack is None:
                return False
            for imsi in attack.imsis:
                _terminate(self._state.procs.pop(imsi, None))
                # Deliberately NOT removed from self._pool -- see
                # _apply_mitigation's comment on why an IMSI's identity
                # must outlive its process once telemetry/mobile_adapter.py
                # has reported it. ue_ip_map.csv/ue_state.json don't need
                # rewriting either, since the pool itself hasn't changed.
        return True

    def stop_all(self) -> None:
        """Full teardown -- every UE process, benign or attacking."""
        self._stop_event.set()
        with self._lock:
            for proc in self._state.procs.values():
                _terminate(proc)
            self._pool.clear()
            self._attacks.clear()

    def active_attacks(self) -> List[GnbAttack]:
        with self._lock:
            return list(self._attacks.values())

    # ------------------------------------------------------------------
    # Mitigation feedback -- mirrors ue_traffic_generator.py's own
    # _rc_watch_loop (interactive mode), adapted for this pool's shape.
    # ------------------------------------------------------------------

    def start_rc_watch(self, tick: float = 1.0) -> None:
        def _loop():
            while not self._stop_event.is_set():
                commands, self._rc_offset = _read_new_commands(self.rc_queue_path, self._rc_offset)
                for command in commands:
                    if command.get("action") == "unblock":
                        continue
                    self._apply_mitigation(command.get("imsi"))
                self._stop_event.wait(tick)

        self._rc_thread = threading.Thread(target=_loop, daemon=True)
        self._rc_thread.start()

    def _apply_mitigation(self, imsi) -> None:
        """
        Kills the real process for a controller-throttled UE. Does NOT
        remove it from self._pool -- confirmed on a real run that doing
        so raced the controller's own later UNTHROTTLE (its presence-
        based unblock check can take tens of seconds to confirm the UE
        genuinely went quiet): telemetry/mobile_adapter.py's
        apply_mitigation() resolves imsi from ue_ip_map.csv at the
        moment the unblock fires, and a since-deleted entry logs
        IMSI_UNRESOLVED, silently dropping that unblock. An orphaned
        pool entry (process dead, identity still resolvable) is
        harmless -- MobileNetworkAdapter only ever emits a
        TelemetryEvent for an IMSI that actually has a fresh CSV row,
        and a dead process produces none.
        """
        with self._lock:
            ue = self._pool.get(imsi)
            if ue is None or ue.benign:
                return
            _terminate(self._state.procs.pop(imsi, None))
            for attack in self._attacks.values():
                if imsi in attack.imsis:
                    attack.imsis.remove(imsi)
        print(f"[GNB-POOL] Mitigado: IMSI {imsi} bloqueado por el controlador")

    # ------------------------------------------------------------------

    def _flush_ue_files(self) -> None:
        """Caller must already hold self._lock."""
        ues = list(self._pool.values())
        _write_ue_ip_map(ues, self.ue_ip_map_path)
        _write_ue_state(ues, self.ue_state_path)
