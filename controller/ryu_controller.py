import os
import sys
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.app.wsgi import WSGIApplication


# =========================
# Fix de imports locales
# =========================
BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


from detectors.syn import SYNDetector
from detectors.udp import UDPDetector
from detectors.icmp import ICMPDetector
from detectors.low_slow import LowSlowDetector

from decision.engine import DecisionEngine
from mitigation.mitigator import FlowMitigator
from core.models import FlowEvent


# =========================
# REST API placeholder
# =========================
class StatsAPI:
    def __init__(self, req, link, data, **config):
        self.req = req
        self.app = data["app"]

    # endpoint simple de prueba
    def get_switches(self, req, **kwargs):
        dps = list(self.app.datapaths.keys())
        return {"switches": dps}


# =========================
# MAIN CONTROLLER
# =========================
class ISPDDOSFlowStats(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # FIX CRÍTICO WSGI
    _CONTEXTS = {
        "wsgi": WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # WSGI REGISTRATION (FIX DEL 404)
        wsgi = kwargs["wsgi"]
        wsgi.register(StatsAPI, {"app": self})

        # datapaths conectados
        self.datapaths = {}

        # IDS components
        self.detectors = [
            SYNDetector(),
            UDPDetector(),
            ICMPDetector(),
            LowSlowDetector()
        ]

        self.decision = DecisionEngine()
        self.mitigator = FlowMitigator()

        # polling thread para flowstats
        self.monitor_thread = hub.spawn(self._monitor_flow_stats)

        self.logger.info("ISP-DDOS FlowStats Controller iniciado correctamente")

    # =========================
    # Switch features
    # =========================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        self.logger.info("Switch conectado: %s", datapath.id)

    # =========================
    # PacketIn (fallback IDS)
    # =========================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        pkt = msg.data

        event = FlowEvent(
            src_ip="0.0.0.0",
            dst_ip="0.0.0.0",
            protocol=0,
            packets=1,
            bytes=len(pkt),
            flow_id="unknown"
        )

        detections = []

        for detector in self.detectors:
            result = detector.detect(event)
            if result:
                detections.append(result)

        decision = self.decision.evaluate(detections)

        if decision:
            self.logger.warning(
                "ATTACK detected: %s from %s",
                decision.detector,
                decision.src_ip
            )

            self.mitigator.block(msg.datapath, decision.src_ip)

    # =========================
    # FLOW STATS MONITOR
    # =========================
    def _monitor_flow_stats(self):
        while True:
            for dp in self.datapaths.values():
                self._request_flow_stats(dp)

            hub.sleep(5)

    def _request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # =========================
    # FLOW STATS RESPONSE
    # =========================
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        total_flows = len(body)

        self.logger.info(
            "Switch %s - Flows activos: %s",
            ev.msg.datapath.id,
            total_flows
        )
