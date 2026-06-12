import os
import sys
import time

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4

from core.models import FlowEvent

from detectors.syn import SYNDetector
from detectors.udp import UDPDetector
from detectors.icmp import ICMPDetector
from detectors.low_slow import LowSlowDetector

from decision.engine import DecisionEngine
from mitigation.mitigator import FlowMitigator


class ISPDDOSFlowStats(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.datapaths = {}

        self.detectors = [
            SYNDetector(),
            UDPDetector(),
            ICMPDetector(),
            LowSlowDetector()
        ]

        self.decision_engine = DecisionEngine()
        self.mitigator = FlowMitigator()

        self.flow_stats = {}

        self.monitor_thread = hub.spawn(self._monitor)

    # -------------------------
    # Track switches
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        self.logger.info("Switch connected: %s", datapath.id)

    # -------------------------
    # Request FlowStats
    # -------------------------
    def _monitor(self):

        while True:

            for dp in self.datapaths.values():
                self._request_flow_stats(dp)

            hub.sleep(2)

    def _request_flow_stats(self, datapath):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # -------------------------
    # Receive FlowStats
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        body = ev.msg.body

        for stat in body:

            if not stat.match.get('ipv4_src'):
                continue

            event = FlowEvent(
                src_ip=stat.match.get('ipv4_src'),
                dst_ip=stat.match.get('ipv4_dst'),
                protocol=stat.match.get('ip_proto', 0),
                packets=stat.packet_count,
                bytes=stat.byte_count,
                flow_id=f"{stat.match.get('ipv4_src')}-{stat.match.get('ipv4_dst')}"
            )

            self._process_event(event, ev.msg.datapath)

    # -------------------------
    # Detection pipeline
    # -------------------------
    def _process_event(self, event, datapath):

        detections = []

        for d in self.detectors:
            result = d.detect(event)
            if result:
                detections.append(result)

        decision = self.decision_engine.evaluate(detections)

        if decision:

            self.logger.warning(
                "[ATTACK] %s src=%s",
                decision.detector,
                decision.src_ip
            )

            self.mitigator.block(
                datapath,
                decision.src_ip
            )
