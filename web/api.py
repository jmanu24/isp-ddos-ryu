from flask import Flask
from flask import jsonify
from flask import render_template
from flask import Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from web.state import dashboard_state

app = Flask(__name__)

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
