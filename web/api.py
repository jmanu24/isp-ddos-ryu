from flask import Flask
from flask import jsonify
from web.state import dashboard_state

app = Flask(__name__)

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

    return jsonify({
        "nodes": [
            {
                "id": s["dpid"]
            }
            for s in dashboard_state.switches.values()
        ],
        "links": []
    })
