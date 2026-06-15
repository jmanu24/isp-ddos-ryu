from flask_socketio import SocketIO
from web.api import app

socketio = SocketIO(
    app,
    cors_allowed_origins="*"
)

def emit_update():

    from web.state import dashboard_state

    socketio.emit(
        "state_update",
        {
            "switches":
            list(
                dashboard_state.switches.values()
            ),

            "events":
            dashboard_state.events[-20:],

            "attacks":
            dashboard_state.attacks[-20:]
        }
    )

def start_server():

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000
    )
