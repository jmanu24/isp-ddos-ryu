"""
bng_interactive.py — menu-driven interactive mode for the Fixed
Broadband Domain (BNG) DDoS simulator, the BNGBlaster equivalent of
simulation/ul_traffic_simulator.py's --interactive mode.

Unlike the mobile simulator (pure Python state, can toggle an
attack_window instantly), this drives a REAL bngblaster process --
launching one takes a few seconds (real DHCP/session establishment),
and its per-session pps is fixed in the JSON config at launch time, not
changeable afterward. So "elegir otro escenario" here means tearing
down the current bngblaster process and launching a new one with that
scenario's config, while "detener"/"iniciar" just toggle the SAME
already-running process's attack traffic on/off (session-traffic-start/
-stop or icmp-client-start/-stop) -- instant, no relaunch needed.

Linux-only, needs root (raw sockets + interface setup) -- same
requirements as bng_traffic_simulator.py and deploy/run_bng_scenario.sh.

Usage:
  sudo python3 simulation/bng_interactive.py
"""

import sys
import threading
import time
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))
from simulation.bng_config import SCENARIOS  # noqa: E402
from simulation.bng_traffic_simulator import BngScenarioSession, DEFAULT_CSV_PATH  # noqa: E402

import subprocess  # noqa: E402

_SETUP_NETNS_SCRIPT = REPO_DIR / "deploy" / "setup_bng_netns.sh"

_SCENARIO_LABELS = {
    "syn_flood": "TCP SYN Flood (1 sesión, un solo atacante)",
    "udp_flood": "UDP Flood (1 sesión, un solo atacante)",
    "icmp_flood": "ICMP Flood (1 sesión, icmp-client real)",
    "distributed_syn_flood": "Distributed TCP SYN Flood (8 sesiones)",
    "low_and_slow": "Low and Slow (8 sesiones, tasa baja continua)",
}

# Same pattern as ul_traffic_simulator.py's _CURRENT_PROMPT/_print_async --
# lets the background polling thread print a status line without
# garbling whatever the user is mid-typing into the command prompt.
_CURRENT_PROMPT = {"text": None}


def _print_async(message: str) -> None:
    prompt_text = _CURRENT_PROMPT["text"]
    if prompt_text:
        print()
        print(message)
        print(prompt_text, end="", flush=True)
    else:
        print(message)


def _prompt(prompt: str, default: str = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    text = f"{prompt}{suffix}: "
    _CURRENT_PROMPT["text"] = text
    try:
        raw = input(text).strip()
    finally:
        _CURRENT_PROMPT["text"] = None
    return raw if raw else (default or "")


def _prompt_scenario() -> str:
    print("\nEscenarios disponibles:")
    options = list(SCENARIOS)
    for i, key in enumerate(options, start=1):
        print(f"  {i}) {key} -- {_SCENARIO_LABELS[key]}")
    while True:
        raw = _prompt(f"Elige un escenario (1-{len(options)} o nombre)", default="1")
        if raw in SCENARIOS:
            return raw
        try:
            idx = int(raw)
            if 1 <= idx <= len(options):
                return options[idx - 1]
        except ValueError:
            pass
        print("  Opción no válida.")


def _run_tick_loop(session: BngScenarioSession, tick_s: float, stop_event: threading.Event, lock: threading.Lock) -> None:
    while not stop_event.is_set():
        with lock:
            try:
                rows = session.tick()
            except (OSError, RuntimeError) as exc:
                _print_async(f"[bng_interactive] tick falló: {exc}")
                rows = []
        if rows:
            total_pps = sum(float(r["pps"]) for r in rows)
            tag = "ATAQUE" if session.attacking else "normal"
            _print_async(f"[bng_interactive] [{tag}] {len(rows)} sesión(es) reportando, "
                         f"pps total ~{total_pps:.1f}")
        stop_event.wait(tick_s)


def _setup_network(teardown: bool = False) -> None:
    args = ["--teardown"] if teardown else []
    subprocess.run(["sudo", str(_SETUP_NETNS_SCRIPT), *args], check=False)


def run_interactive(tick_s: float = 1.0) -> None:
    if sys.platform != "linux":
        print("ERROR: bngblaster requires Linux (raw sockets) -- run this on the Ubuntu test VM, not here.",
              file=sys.stderr)
        sys.exit(1)

    print("=== Simulador interactivo del dominio Broadband (BNGBlaster real) ===")
    print(f"Telemetría en {DEFAULT_CSV_PATH}")
    print("Configurando red (veth + dnsmasq, idempotente)...")
    _setup_network()

    session = None
    thread = None
    stop_event = None
    lock = threading.Lock()

    def _teardown_current():
        nonlocal session, thread, stop_event
        if stop_event is not None:
            stop_event.set()
        if thread is not None:
            thread.join(timeout=5)
        if session is not None:
            session.stop()
        session, thread, stop_event = None, None, None

    try:
        while True:
            scenario = _prompt_scenario()
            target_ip = _prompt("IP objetivo simulada", default="10.0.2.10")

            _teardown_current()
            session = BngScenarioSession(scenario=scenario, target_ip=target_ip)
            session.start()
            if not session.attacking:
                session.start_attack()

            stop_event = threading.Event()
            thread = threading.Thread(
                target=_run_tick_loop, args=(session, tick_s, stop_event, lock), daemon=True,
            )
            thread.start()

            print(f"\n[bng_interactive] Ataque '{scenario}' activo contra {target_ip}.")
            print("Comandos: 'detener' (para el tráfico, mantiene la sesión) | "
                  "'iniciar' (reanuda) | 'cambiar' (elegir otro escenario) | 'salir'")

            while True:
                _CURRENT_PROMPT["text"] = "> "
                try:
                    cmd = input("> ").strip().lower()
                finally:
                    _CURRENT_PROMPT["text"] = None

                if cmd == "":
                    continue
                if cmd in ("detener", "stop", "d"):
                    with lock:
                        if session.attacking:
                            session.stop_attack()
                            print("[bng_interactive] Tráfico de ataque detenido (sesión sigue activa).")
                        else:
                            print("[bng_interactive] Ya estaba detenido.")
                elif cmd in ("iniciar", "start", "i"):
                    with lock:
                        if not session.attacking:
                            session.start_attack()
                            print("[bng_interactive] Tráfico de ataque reanudado.")
                        else:
                            print("[bng_interactive] Ya estaba corriendo.")
                elif cmd in ("cambiar", "change", "c"):
                    print("[bng_interactive] Deteniendo escenario actual...")
                    break
                elif cmd in ("salir", "exit", "quit", "q"):
                    raise KeyboardInterrupt
                else:
                    print("  Comando no reconocido -- 'detener', 'iniciar', 'cambiar' o 'salir'.")
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        print("[bng_interactive] cerrando...")
        _teardown_current()
        respuesta = ""
        try:
            respuesta = input("¿Limpiar la red (veth/dnsmasq) creada? [S/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            pass
        if respuesta not in ("n", "no"):
            print("[bng_interactive] limpiando red...")
            _setup_network(teardown=True)
        print("[bng_interactive] listo")


if __name__ == "__main__":
    run_interactive()
