
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
from ryu.controller.handler import (
    MAIN_DISPATCHER,
    CONFIG_DISPATCHER,
    set_ev_cls
)
from ryu.ofproto import ofproto_v1_3

from ryu.lib import hub
from ryu.lib.packet import packet, ethernet

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
        self.mac_to_port = {}

        self.detectors = [
            SYNDetector(),
            UDPDetector(),
            ICMPDetector(),
            LowSlowDetector()
        ]

        self.decision_engine = DecisionEngine()
        self.mitigator = FlowMitigator()

        self.monitor_thread = hub.spawn(self._monitor)

    # -------------------------
    # SWITCH CONNECT
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        # table-miss
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                   ofproto.OFPCML_NO_BUFFER)
        ]

        self.add_flow(datapath, 0, match, actions)

        self.logger.info("Switch connected: %s", datapath.id)

    # -------------------------
    # FLOW INSTALL
    # -------------------------
    def add_flow(self, datapath, priority, match, actions):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )

        datapath.send_msg(mod)

    # -------------------------
    # LEARNING SWITCH (FORWARDING)
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # learn MAC
        self.mac_to_port[dpid][src] = in_port

        # decide output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install flow rule
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        # send packet
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )

        datapath.send_msg(out)

    # -------------------------
    # FLOWSTATS POLLING
    # -------------------------
    def _monitor(self):

        while True:

            for dp in self.datapaths.values():
                self._request_stats(dp)

            hub.sleep(2)

    def _request_stats(self, datapath):

        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # -------------------------
    # FLOWSTATS HANDLER
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):

        for stat in ev.msg.body:

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
    # DETECTION PIPELINE
    # -------------------------
    def _process_event(self, event, datapath):

        detections = []

        for d in self.detectors:
            r = d.detect(event)
            if r:
                detections.append(r)

        decision = self.decision_engine.evaluate(detections)

        if decision:

            self.logger.warning(
                "[ATTACK] %s src=%s score=%s",
                decision.attack_type,
                decision.src_ip,
                decision.score
            )

            self.mitigator.block(
                datapath,
                decision.src_ip
            )
