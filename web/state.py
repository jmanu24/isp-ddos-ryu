from datetime import datetime


class DashboardState:

    def __init__(self):

        self.switches = {}
        self.events = []
        self.attacks = []

        self.topology = {
            "nodes": [],
            "links": []
        }

    def add_switch(self, dpid):

        self.switches[str(dpid)] = {
            "dpid": str(dpid),
            "status": "UP",
            "last_seen": datetime.now().isoformat(),
            "byte_rate": 0,
            "packet_rate": 0
        }

    def update_stats(
        self,
        dpid,
        byte_rate,
        packet_rate
    ):

        dpid = str(dpid)

        if dpid not in self.switches:
            self.add_switch(dpid)

        self.switches[dpid]["byte_rate"] = byte_rate
        self.switches[dpid]["packet_rate"] = packet_rate
        self.switches[dpid]["last_seen"] = datetime.now().isoformat()

    def update_topology(
        self,
        nodes,
        links
    ):

        self.topology = {
            "nodes": nodes,
            "links": links
        }

    def add_event(self, text):

        self.events.append({
            "timestamp": datetime.now().isoformat(),
            "message": text
        })

        self.events = self.events[-500:]

    def add_attack(
        self,
        dpid,
        byte_rate,
        packet_rate
    ):

        self.attacks.append({
            "timestamp": datetime.now().isoformat(),
            "switch": str(dpid),
            "byte_rate": byte_rate,
            "packet_rate": packet_rate
        })

        self.attacks = self.attacks[-200:]


dashboard_state = DashboardState()
