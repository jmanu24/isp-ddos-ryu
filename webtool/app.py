"""
webtool/app.py — standalone web app for the unified multi-domain DDoS
attack launcher. Deliberately separate from web/ (the existing read-only
dashboard, port 5000, embedded in the ryu-manager process): different
process, different port, its own Flask/SocketIO instance -- this module
never imports from web/, it only ever talks to it as a black-box HTTP
client (see _poll_dashboard_events below), per the user's own explicit
"standalone app" choice.

Requires root -- Mininet, hping3, bngblaster and the BNG netns move
(topologies/star_topology.py's attach_bng_gateway_to_r1) all need it.

Usage:
  sudo python3 webtool/app.py
"""

import json
import os
import signal
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))

from flask import Flask, jsonify, render_template, request  # noqa: E402
from flask_socketio import SocketIO  # noqa: E402

from webtool.orchestrator import Orchestrator  # noqa: E402
from webtool.state import webtool_state  # noqa: E402

WEBTOOL_PORT = 5050
# The existing dashboard's own /api/events (web/api.py) -- polled as a
# plain HTTP client, exactly like any other consumer of that endpoint.
DASHBOARD_EVENTS_URL = "http://127.0.0.1:5000/api/events"

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
orchestrator = Orchestrator()

_VALID_DOMAINS = ("enterprise", "mobile", "broadband")
_VALID_ATTACK_TYPES = ("SYN", "UDP", "ICMP")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/controller/start", methods=["POST"])
def controller_start():
    return jsonify(orchestrator.start_controller())


@app.route("/api/controller/stop", methods=["POST"])
def controller_stop():
    return jsonify(orchestrator.stop_controller())


@app.route("/api/controller/status")
def controller_status():
    return jsonify({"status": webtool_state.controller_status})


@app.route("/api/topology/start", methods=["POST"])
def topology_start():
    return jsonify(orchestrator.start_topology())


@app.route("/api/topology/stop", methods=["POST"])
def topology_stop():
    return jsonify(orchestrator.stop_topology())


@app.route("/api/topology/status")
def topology_status():
    return jsonify({
        "status": webtool_state.topology_status,
        "nodes": list(webtool_state.nodes.values()),
    })


@app.route("/api/attack/start", methods=["POST"])
def attack_start():
    body = request.get_json(force=True, silent=True) or {}
    domain = body.get("domain")
    switch_indices = body.get("switch_indices")
    attack_type = body.get("attack_type")
    target_ip = body.get("target_ip")
    duration = body.get("duration")
    dst_port = body.get("dst_port")
    count_per_node = body.get("count_per_node", 1)

    if domain not in _VALID_DOMAINS:
        return jsonify({"ok": False, "error": f"domain invalido: {domain}"}), 400
    if not isinstance(switch_indices, list) or not switch_indices:
        return jsonify({"ok": False, "error": "switch_indices debe ser una lista no vacia"}), 400
    if attack_type not in _VALID_ATTACK_TYPES:
        return jsonify({"ok": False, "error": f"attack_type invalido: {attack_type}"}), 400
    if not target_ip:
        return jsonify({"ok": False, "error": "target_ip requerido"}), 400
    if target_ip == orchestrator.central_server_ip():
        return jsonify({"ok": False, "error": "el servidor central no puede ser objetivo de un ataque"}), 400
    if target_ip not in orchestrator.valid_targets():
        return jsonify({"ok": False, "error": f"target_ip debe ser uno de los hosts reales de la topologia: {target_ip}"}), 400

    if dst_port is None:
        dst_port = 443 if attack_type == "SYN" else 0

    if domain == "enterprise":
        result = orchestrator.start_enterprise_attack(switch_indices, attack_type, dst_port, target_ip, duration)
    elif domain == "mobile":
        result = orchestrator.start_mobile_attack(
            switch_indices, attack_type, dst_port, target_ip,
            count_per_gnb=count_per_node, duration=duration,
        )
    else:
        result = orchestrator.start_broadband_attack(switch_indices, attack_type, target_ip, duration)

    return jsonify(result), (200 if result.get("ok") else 400)


@app.route("/api/attack/stop", methods=["POST"])
def attack_stop():
    body = request.get_json(force=True, silent=True) or {}
    attack_id = body.get("attack_id")
    if not attack_id:
        return jsonify({"ok": False, "error": "attack_id requerido"}), 400
    result = orchestrator.stop_attack(attack_id)
    return jsonify(result), (200 if result.get("ok") else 400)


@app.route("/api/attacks")
def attacks():
    return jsonify(list(webtool_state.active_attacks.values()))


@app.route("/api/state")
def state():
    return jsonify(webtool_state.to_dict())


_dashboard_events_seen = 0


def _poll_dashboard_events() -> None:
    """Forwards the existing dashboard's DETECTION/MITIGATION events
    into this app's own event log, so the webtool UI shows live
    controller activity without importing anything from web/. Uses
    urllib (stdlib), not the `requests` library, to avoid adding a new
    dependency requirements.txt doesn't already list."""
    global _dashboard_events_seen
    try:
        with urllib.request.urlopen(DASHBOARD_EVENTS_URL, timeout=2) as resp:
            events = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return
    if not isinstance(events, list):
        return
    if len(events) < _dashboard_events_seen:
        # Dashboard restarted (its own event log reset) -- start over.
        _dashboard_events_seen = 0
    new_events = events[_dashboard_events_seen:]
    _dashboard_events_seen = len(events)
    for ev in new_events:
        webtool_state.add_event(f"[controlador] {ev.get('message', ev)}")


def _reconciliation_loop() -> None:
    while True:
        _poll_dashboard_events()
        socketio.emit("state_update", webtool_state.to_dict())
        socketio.sleep(1)


@socketio.on("connect")
def on_connect():
    socketio.emit("state_update", webtool_state.to_dict())


def _graceful_shutdown(signum, frame):
    """
    Confirmed on a real run: killing this process (Ctrl-C, or any other
    SIGINT/SIGTERM) with no handler at all leaves the live Mininet net,
    its veth pairs, and every hping3/bngblaster/dnsmasq process it
    started completely orphaned -- orchestrator.stop_topology() never
    runs, so nothing tears any of it down. The NEXT start of this app
    then fails outright the moment build_topology() tries to recreate
    an interface pair that still exists ("RTNETLINK answers: File
    exists"), and needs a manual `sudo mn -c` before it can recover.
    Tearing down the topology (and the controller, if this process
    itself launched it) here avoids that.
    """
    print("\n[webtool] apagando -- deteniendo topologia y controlador...")
    try:
        orchestrator.stop_topology()
    except Exception as exc:
        print(f"[webtool] error al detener la topologia: {exc}", file=sys.stderr)
    try:
        orchestrator.stop_controller()
    except Exception as exc:
        print(f"[webtool] error al detener el controlador: {exc}", file=sys.stderr)
    sys.exit(0)


def main():
    if os.geteuid() != 0:
        print("ERROR: corre esto como root -- Mininet/hping3/bngblaster necesitan sockets raw.", file=sys.stderr)
        sys.exit(1)
    signal.signal(signal.SIGINT, _graceful_shutdown)
    signal.signal(signal.SIGTERM, _graceful_shutdown)
    socketio.start_background_task(_reconciliation_loop)
    socketio.run(app, host="0.0.0.0", port=WEBTOOL_PORT)


if __name__ == "__main__":
    main()
