from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

from forwarding.learning_switch import LearningSwitch
from collectors.flow_collector import FlowCollector


class FlowStatsIDS(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):

        super(FlowStatsIDS, self).__init__(*args, **kwargs)

        self.datapaths = {}

        self.forwarding = LearningSwitch()

        self.collector = FlowCollector()

        self.byte_threshold = 1e6
        self.packet_threshold = 1000

        self.monitor_thread = hub.spawn(self._monitor)

        self.logger.info("FlowStats IDS iniciado")

    # -------------------------------------------------
    # SWITCH CONNECT
    # -------------------------------------------------

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath

        self.datapaths[datapath.id] = datapath

        self.forwarding.switch_features_handler(
            datapath
        )

        self.logger.info(
            "Switch conectado: %s",
            datapath.id
        )

    # -------------------------------------------------
    # PACKET IN
    # -------------------------------------------------

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, ev):

        self.forwarding.packet_in_handler(ev)

    # -------------------------------------------------
    # MONITOR
    # -------------------------------------------------

    def _monitor(self):

        while True:

            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)

            hub.sleep(5)

    def _request_flow_stats(self, datapath):

        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)

        datapath.send_msg(req)

    # -------------------------------------------------
    # FLOW STATS
    # -------------------------------------------------

    @set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER
    )
    def flow_stats_reply_handler(self, ev):

        dpid = ev.msg.datapath.id

        metrics = self.collector.process_stats(
            dpid,
            ev.msg.body
        )

        byte_rate = metrics["byte_rate"]
        packet_rate = metrics["packet_rate"]

        self.logger.info(
            "SW %s | Byte/s: %.2f | Packet/s: %.2f",
            dpid,
            byte_rate,
            packet_rate
        )

        if (
            byte_rate > self.byte_threshold
            or
            packet_rate > self.packet_threshold
        ):

            self.logger.warning(
                "POSIBLE DDoS SW=%s Byte/s=%.2f Packet/s=%.2f",
                dpid,
                byte_rate,
                packet_rate
            )
