from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls
)
from ryu.ofproto import ofproto_v1_3

from forwarding.learning_switch import LearningSwitch
from collectors.flow_collector import FlowCollector

from detectors.syn import SYNDetector
from detectors.udp import UDPDetector
from detectors.icmp import ICMPDetector
from detectors.low_slow import LowSlowDetector

from decision.engine import DecisionEngine
from mitigation.mitigator import FlowMitigator


class ISPDDOS(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.forwarder = LearningSwitch()
        self.collector = FlowCollector()

        self.detectors = [
            SYNDetector(),
            UDPDetector(),
            ICMPDetector(),
            LowSlowDetector()
        ]

        self.decision_engine = DecisionEngine()
        self.mitigator = FlowMitigator()

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath

        self.forwarder.install_table_miss(
            datapath
        )

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        self.forwarder.handle_packet(ev)

        flow = self.collector.collect(
            ev.msg
        )

        if not flow:
            return

        detections = []

        for detector in self.detectors:

            result = detector.detect(flow)

            if result:
                detections.append(result)

        decision = self.decision_engine.evaluate(
            detections
        )

        if decision:

            self.logger.warning(
                "Attack detected %s",
                decision.detector
            )

            self.mitigator.block(
                ev.msg.datapath,
                decision.src_ip
            )
