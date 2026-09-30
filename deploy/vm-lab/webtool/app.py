"""
webtool/app.py -- standalone web app for the distributed VM lab
(deploy/vm-lab). Separate process/port from the mininet webtool
(webtool/app.py at the repo root, port 5050) -- this is a different lab
entirely (real VMs over SSH/govc/Ansible, not Mininet), so it gets its
own port and never imports anything from the mininet webtool.

Requires: sshpass, govc, ansible-playbook all on PATH, and
../.govc.env / ../generated/ansible/inventory.ini already in place
(see deploy/vm-lab/README.md). Does NOT need root -- everything here is
either a plain SSH client call or a local subprocess (govc,
ansible-playbook), unlike the mininet webtool which needs raw sockets.

Usage:
  cd deploy/vm-lab && python3 -m webtool.app
"""

import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

VM_LAB_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(VM_LAB_DIR))

from flask import Flask, jsonify, render_template, request  # noqa: E402
from flask_socketio import SocketIO  # noqa: E402

from webtool import attacks, ansible_runner, govc_ops, kpm, logs, metrics, status_checks  # noqa: E402
from webtool.inventory import BRINGUP_STEPS, NODES, to_topology_dict  # noqa: E402
from webtool.ansible_runner import RECONNECT_PLAYBOOK  # noqa: E402
from webtool.state import vmlab_state  # noqa: E402

VMLAB_WEBTOOL_PORT = 5060

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
_pool = ThreadPoolExecutor(max_workers=12)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/topology")
def topology():
    return jsonify(to_topology_dict())


@app.route("/api/state")
def state():
    return jsonify(vmlab_state.to_dict())


# ---------------------------------------------------------------- power --

@app.route("/api/power/status")
def power_status():
    return jsonify(govc_ops.power_states())


@app.route("/api/power/<vm_name>/<action>", methods=["POST"])
def power_action(vm_name, action):
    if action not in ("on", "off"):
        return jsonify({"ok": False, "error": "accion invalida (on|off)"}), 400
    ok = govc_ops.power(vm_name, on=(action == "on"))
    if ok:
        vmlab_state.add_event(f"POWER: {vm_name} -> {action}")
    return jsonify({"ok": ok}), (200 if ok else 500)


# -------------------------------------------------------------- bring-up --

@app.route("/api/bringup/steps")
def bringup_steps():
    return jsonify([{"label": label, "tags": tags} for label, tags in BRINGUP_STEPS])


@app.route("/api/bringup/full", methods=["POST"])
def bringup_full():
    body = request.get_json(force=True, silent=True) or {}
    power_cycle = bool(body.get("power_cycle", True))
    skip_victim = bool(body.get("skip_victim", True))
    result = ansible_runner.run_playbook(
        RECONNECT_PLAYBOOK, "reconnect_mobile_domain (full)",
        skip_tags=["victim"] if skip_victim else None,
        extra_vars={"power_cycle": str(power_cycle).lower()},
    )
    return jsonify(result), (200 if result.get("ok") else 409)


@app.route("/api/bringup/step", methods=["POST"])
def bringup_step():
    body = request.get_json(force=True, silent=True) or {}
    tag = body.get("tag")
    if not tag:
        return jsonify({"ok": False, "error": "tag requerido"}), 400
    result = ansible_runner.run_playbook(
        RECONNECT_PLAYBOOK, f"reconnect_mobile_domain (--tags {tag})",
        tags=[tag], extra_vars={"power_cycle": "false"},
    )
    return jsonify(result), (200 if result.get("ok") else 409)


@app.route("/api/bringup/cancel", methods=["POST"])
def bringup_cancel():
    return jsonify(ansible_runner.cancel_current())


# ----------------------------------------------------------------- logs --

@app.route("/api/logs/sources/<node_name>")
def logs_sources(node_name):
    return jsonify(logs.sources_for(node_name))


@app.route("/api/logs/<node_name>/<source_id>")
def logs_fetch(node_name, source_id):
    lines = request.args.get("lines", default=300, type=int)
    return jsonify(logs.fetch_log(node_name, source_id, lines))


# --------------------------------------------------------------- attacks --

@app.route("/api/attack/sources/<domain>")
def attack_sources(domain):
    return jsonify(attacks.valid_sources(domain))


@app.route("/api/attack/start", methods=["POST"])
def attack_start():
    body = request.get_json(force=True, silent=True) or {}
    domain = body.get("domain")
    source = body.get("source")
    attack_type = body.get("attack_type")
    target_ip = body.get("target_ip")
    dst_port = body.get("dst_port") or (443 if attack_type == "SYN" else 0)
    if domain not in ("enterprise", "bgp", "broadband", "mobile"):
        return jsonify({"ok": False, "error": f"dominio invalido: {domain}"}), 400
    if attack_type not in ("SYN", "UDP", "ICMP"):
        return jsonify({"ok": False, "error": f"attack_type invalido: {attack_type}"}), 400
    result = attacks.start_attack(domain, source, attack_type, target_ip, dst_port)
    return jsonify(result), (200 if result.get("ok") else 400)


@app.route("/api/attack/stop", methods=["POST"])
def attack_stop():
    body = request.get_json(force=True, silent=True) or {}
    attack_id = body.get("attack_id")
    if not attack_id:
        return jsonify({"ok": False, "error": "attack_id requerido"}), 400
    result = attacks.stop_attack(attack_id)
    return jsonify(result), (200 if result.get("ok") else 400)


# ------------------------------------------------------------------ KPM --

@app.route("/api/kpm")
def kpm_snapshot():
    return jsonify({"samples": vmlab_state.kpm_samples, "mitigation_events": vmlab_state.mitigation_events})


# ------------------------------------------------------------- polling ---

def _poll_status():
    futures = {n.name: _pool.submit(status_checks.probe_node, n.name, n.role) for n in NODES}
    for name, fut in futures.items():
        try:
            checks = fut.result(timeout=20)
        except Exception as exc:  # noqa: BLE001
            checks = {"reachable": False, "error": str(exc)}
        vmlab_state.set_node_status(name, {"checks": checks})


def _poll_metrics():
    futures = {n.name: _pool.submit(metrics.sample_node, n.name) for n in NODES}
    for name, fut in futures.items():
        try:
            sample = fut.result(timeout=20)
        except Exception:  # noqa: BLE001
            sample = None
        if sample:
            vmlab_state.set_metrics(name, sample)


def _poll_kpm():
    try:
        samples = kpm.poll_kpm_samples()
        vmlab_state.set_kpm_samples(samples)
    except Exception:  # noqa: BLE001
        pass
    try:
        lines = kpm.tail_mitigation_events(lines=30)
        vmlab_state.add_mitigation_events(lines)
    except Exception:  # noqa: BLE001
        pass


def _poll_power():
    try:
        states = govc_ops.power_states()
    except Exception:  # noqa: BLE001
        states = {}
    for n in NODES:
        power = states.get(n.name, "unknown")
        status = vmlab_state.node_status.get(n.name, {})
        status["power"] = power
        vmlab_state.set_node_status(n.name, status)


def _reconciliation_loop():
    tick = 0
    while True:
        try:
            _poll_power()
            _poll_status()
            if tick % 2 == 0:      # metrics/KPM every ~20s, status every ~10s
                _poll_metrics()
                _poll_kpm()
            socketio.emit("state_update", vmlab_state.to_dict())
        except Exception as exc:  # noqa: BLE001
            vmlab_state.add_event(f"[webtool] error en el loop de reconciliacion: {exc}")
        tick += 1
        socketio.sleep(10)


@socketio.on("connect")
def on_connect():
    socketio.emit("state_update", vmlab_state.to_dict())


def main():
    socketio.start_background_task(_reconciliation_loop)
    socketio.run(app, host="0.0.0.0", port=VMLAB_WEBTOOL_PORT, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
