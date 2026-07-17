from flask import Flask
from flask import jsonify
from flask import render_template
from flask import request
from flask import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from web.state import dashboard_state

app = Flask(__name__)

# Injected by the Ryu controller after startup so the /blocks unblock
# endpoint can call force_unblock() on the live orchestrator instance.
_orchestrator = None


def set_orchestrator(orchestrator) -> None:
    global _orchestrator
    _orchestrator = orchestrator

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/metrics")
def metrics():
    # Scraped by Prometheus; Grafana queries Prometheus for dashboards —
    # this is the only place traffic/attack data is exposed for that.
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@app.route("/api/switches")
def switches():

    return jsonify(
        list(
            dashboard_state.switches.values()
        )
    )

@app.route("/api/events")
def events():

    return jsonify(
        dashboard_state.events
    )

@app.route("/api/attacks")
def attacks():

    return jsonify(
        dashboard_state.attacks
    )

@app.route("/api/topology")
def topology():

    return jsonify(dashboard_state.topology)

@app.route("/blocks")
def blocks_page():
    return render_template("blocks.html")

@app.route("/api/blocks")
def blocks_api():
    return jsonify(dashboard_state.active_blocks)

@app.route("/api/blocks/unblock", methods=["POST"])
def blocks_unblock():
    if _orchestrator is None:
        return jsonify({"ok": False, "error": "orchestrator not available"}), 503

    data = request.get_json(silent=True) or {}
    src_ip   = data.get("src_ip", "")
    dst_ip   = data.get("dst_ip", "")
    dst_port = int(data.get("dst_port", 0))
    protocol = data.get("protocol", "")

    if not all([src_ip, dst_ip, protocol]):
        return jsonify({"ok": False, "error": "missing fields"}), 400

    removed = _orchestrator.force_unblock(src_ip, dst_ip, dst_port, protocol)
    if not removed:
        return jsonify({"ok": False, "error": "block not found"}), 404

    return jsonify({"ok": True})
