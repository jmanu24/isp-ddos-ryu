from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

import threading

from forwarding.learning_switch import LearningSwitch
from collectors.flow_collector import FlowCollector

from web.state import dashboard_state
from web.socket_server import (
    start_server,
    emit_update
)


class FlowStatsIDS(app_manager.RyuApp):

    OFP_VERSIONS = [
        ofproto_v1_3.OFP_VERSION
    ]

    def __init__(self, *args, **kwargs):

        super(FlowStatsIDS, self).__init__(
            *args,
            **kwargs
        )

        self.datapaths = {}

        self.forwarding = LearningSwitch()

        self.collector = FlowCollector()

        self.byte_threshold = 1e6
        self.packet_threshold = 1000

        self.monitor_thread = hub.spawn(
            self._monitor
        )

        threading.Thread(
            target=start_server,
            daemon=True
        ).start()

        self.logger.info(
            "Dashboard Web iniciado en puerto 5000"
        )

        self.logger.info(
            "FlowStats IDS iniciado"
        )

    # -------------------------------------------------
    # SWITCH CONNECT
    # -------------------------------------------------

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath

        self.datapaths[
            datapath.id
        ] = datapath

        self.forwarding.switch_features_handler(
            datapath
        )

        dashboard_state.add_switch(
            datapath.id
        )

        dashboard_state.add_event(
            f"Switch conectado: {datapath.id}"
        )

        emit_update()

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

        self.forwarding.packet_in_handler(
            ev
        )

    # -------------------------------------------------
    # MONITOR THREAD
    # -------------------------------------------------

    def _monitor(self):

        while True:

            for dp in list(
                self.datapaths.values()
            ):

                try:

                    self._request_flow_stats(
                        dp
                    )

                except Exception as e:

                    self.logger.error(
                        "Error solicitando stats: %s",
                        str(e)
                    )

            hub.sleep(5)

    def _request_flow_stats(
        self,
        datapath
    ):

        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(
            datapath
        )

        datapath.send_msg(
            req
        )

    # -------------------------------------------------
    # FLOW STATS
    # -------------------------------------------------

    @set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER
    )
    def flow_stats_reply_handler(
        self,
        ev
    ):

        dpid = ev.msg.datapath.id

        metrics = self.collector.process_stats(
            dpid,
            ev.msg.body
        )

        byte_rate = metrics.get(
            "byte_rate",
            0
        )

        packet_rate = metrics.get(
            "packet_rate",
            0
        )

        dashboard_state.update_stats(
            dpid,
            byte_rate,
            packet_rate
        )

        emit_update()

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

            dashboard_state.add_attack(
                dpid,
                byte_rate,
                packet_rate
            )

            dashboard_state.add_event(
                (
                    f"POSIBLE DDoS "
                    f"SW={dpid} "
                    f"Byte/s={byte_rate:.2f} "
                    f"Packet/s={packet_rate:.2f}"
                )
            )

            emit_update()

            self.logger.warning(
                "POSIBLE DDoS SW=%s Byte/s=%.2f Packet/s=%.2f",
                dpid,
                byte_rate,
                packet_rate
            )
