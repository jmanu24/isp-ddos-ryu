from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3

from detectors.syn import SYNDetector
from detectors.udp import UDPDetector
from detectors.icmp import ICMPDetector
from detectors.low_slow import LowSlowDetector

from decision.engine import DecisionEngine
from mitigation.mitigator import FlowMitigator

from core.models import FlowEvent


class ISPDDOS(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.detectors = [
            SYNDetector(),
            UDPDetector(),
            ICMPDetector(),
            LowSlowDetector()
        ]

        self.decision = DecisionEngine()
        self.mitigator = FlowMitigator()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):

        msg = ev.msg
        pkt = msg.data

        # simplificado: en producción parsear con ryu.lib.packet
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        protocol = 0
        packets = 1
        bytes_ = len(pkt)

        event = FlowEvent(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            packets=packets,
            bytes=bytes_,
            flow_id=f"{src_ip}-{dst_ip}"
        )

        detections = []

        for d in self.detectors:
            r = d.detect(event)
            if r:
                detections.append(r)

        decision = self.decision.evaluate(detections)

        if decision:
            self.logger.warning(
                "ATTACK detected: %s from %s",
                decision.detector,
                decision.src_ip
            )

            self.mitigator.block(
                msg.datapath,
                decision.src_ip
            )
