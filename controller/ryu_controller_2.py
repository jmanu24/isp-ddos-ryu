from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls
)

from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

from ryu.topology import event
from ryu.topology.api import (
    get_switch,
    get_link
)

import threading

from forwarding.learning_switch import LearningSwitch
from collectors.flow_collector import FlowCollector
from collectors.ddos_collector import DDoSCollector

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

        super(FlowStatsIDS, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.port_stats_prev = {}

        self.forwarding = LearningSwitch()
        self.collector = FlowCollector()
        self.ddos_collector = DDoSCollector()

        self.byte_threshold = 1e6
        self.packet_threshold = 1000

        self.monitor_thread = hub.spawn(self._monitor)

        threading.Thread(
            target=start_server,
            daemon=True
        ).start()

        self.logger.info("Dashboard Web iniciado en puerto 5000")
        self.logger.info("FlowStats IDS iniciado")

    # ---------------------------------------------
    # TOPOLOGY
    # ---------------------------------------------

    def update_topology(self):

        try:

            switch_list = get_switch(self, None)
            link_list = get_link(self, None)

            nodes = []

            for sw in switch_list:
                nodes.append({
                    "id": str(sw.dp.id),
                    "label": f"s{sw.dp.id}"
                })

            links = []

            for link in link_list:
                links.append({
                    "source": str(link.src.dpid),
                    "target": str(link.dst.dpid)
                })

            dashboard_state.update_topology(nodes, links)
            emit_update()

        except Exception as e:
            self.logger.error("Topology update error: %s", str(e))

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):

        self.logger.info("Switch detectado")

        dashboard_state.add_event("Switch agregado a topologia")

        self.update_topology()

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):

        self.logger.info("Switch removido")

        dashboard_state.add_event("Switch removido de topologia")

        self.update_topology()

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):

        dashboard_state.add_event("Nuevo enlace detectado")

        self.update_topology()

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):

        dashboard_state.add_event("Enlace eliminado")

        self.update_topology()

    # ---------------------------------------------
    # SWITCH FEATURES
    # ---------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath

        self.datapaths[datapath.id] = datapath

        self.forwarding.switch_features_handler(datapath)

        dashboard_state.add_switch(datapath.id)
        dashboard_state.add_event(f"Switch conectado: {datapath.id}")

        emit_update()

        self.logger.info("Switch conectado: %s", datapath.id)

    # ---------------------------------------------
    # PACKET IN
    # ---------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        result = self.ddos_collector.process_packet(
            ev.msg
        )

        if result:

            self.logger.warning(
                "DDoS_STATS "
                "DST=%s:%s "
                "PROTO=%s "
                "PPS=%.2f "
                "BPS=%.2f",
                result["dst_ip"],
                result["dst_port"],
                result["protocol"],
                result["pps"],
                result["bps"]
            )

            if result["pps"] > self.packet_threshold:

                dashboard_state.add_event(
                    f"DDoS DETECTADO "
                    f"DST={result['dst_ip']}:{result['dst_port']} "
                    f"PPS={result['pps']:.2f}"
                )

                emit_update()

        self.forwarding.packet_in_handler(ev)
 
    # ---------------------------------------------
    # MONITOR
    # ---------------------------------------------

    def _monitor(self):

        while True:

            for dp in list(self.datapaths.values()):

                try:
                    self._request_flow_stats(dp)
                    self._request_port_stats(dp)

                except Exception as e:
                    self.logger.error("Stats error: %s", str(e))

            hub.sleep(1)

    def _request_flow_stats(self, datapath):

        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _request_port_stats(self, datapath):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(
            datapath,
            0,
            ofproto.OFPP_ANY
        )

        datapath.send_msg(req)

    # ---------------------------------------------
    # FLOW STATS
    # ---------------------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):

        dpid = ev.msg.datapath.id

        flows = self.collector.process_stats(
            dpid,
            ev.msg.body
        )

        for flow in flows:

            self.logger.info(
                "FLOW SW=%s "
                "%s:%s -> %s:%s "
                "PROTO=%s "
                "B/s=%.2f "
                "P/s=%.2f",
                dpid,
                flow["src_ip"],
                flow["src_port"],
                flow["dst_ip"],
                flow["dst_port"],
                flow["protocol"],
                flow["byte_rate"],
                flow["packet_rate"]
            )

            total_byte_rate = 0
            total_packet_rate = 0

            for flow in flows:

                total_byte_rate += flow["byte_rate"]
                total_packet_rate += flow["packet_rate"]

                self.logger.info(
                    "FLOW SW=%s "
                    "%s:%s -> %s:%s "
                    "PROTO=%s "
                    "B/s=%.2f "
                    "P/s=%.2f",
                    dpid,
                    flow["src_ip"],
                    flow["src_port"],
                    flow["dst_ip"],
                    flow["dst_port"],
                    flow["protocol"],
                    flow["byte_rate"],
                    flow["packet_rate"]
                )

            dashboard_state.update_stats(
                dpid,
                total_byte_rate,
                total_packet_rate
            )

            emit_update()

            self.logger.info(
                "SW %s | Byte/s %.2f | Packet/s %.2f",
                dpid,
                total_byte_rate,
                total_packet_rate
            )

            if (
                total_byte_rate > self.byte_threshold
                or total_packet_rate > self.packet_threshold
            ):

                dashboard_state.add_attack(
                    dpid,
                    total_byte_rate,
                    total_packet_rate
                )

                dashboard_state.add_event(
                    f"POSIBLE DDoS SW={dpid} "
                    f"Byte/s={total_byte_rate:.2f} "
                    f"Packet/s={total_packet_rate:.2f}"
                )

                emit_update()

                self.logger.warning(
                    "POSIBLE DDoS SW=%s Byte/s=%.2f Packet/s=%.2f",
                    dpid,
                    total_byte_rate,
                    total_packet_rate
                )


    # ---------------------------------------------
    # PORT STATS
    # ---------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):

        dpid = ev.msg.datapath.id
        ofproto = ev.msg.datapath.ofproto

        for stat in sorted(ev.msg.body, key=lambda x: x.port_no):

            if stat.port_no == ofproto.OFPP_LOCAL:
                continue

            key = (dpid, stat.port_no)

            current_rx_bytes = stat.rx_bytes
            current_tx_bytes = stat.tx_bytes
            current_rx_packets = stat.rx_packets
            current_tx_packets = stat.tx_packets

            if key in self.port_stats_prev:

                previous = self.port_stats_prev[key]

                rx_byte_rate = current_rx_bytes - previous["rx_bytes"]
                tx_byte_rate = current_tx_bytes - previous["tx_bytes"]

                rx_packet_rate = current_rx_packets - previous["rx_packets"]
                tx_packet_rate = current_tx_packets - previous["tx_packets"]

                total_byte_rate = rx_byte_rate + tx_byte_rate
                total_packet_rate = rx_packet_rate + tx_packet_rate

                self.logger.info(
                    "PORT | SW=%s PORT=%s RX_B/s=%d TX_B/s=%d RX_P/s=%d TX_P/s=%d TOTAL_B/s=%d TOTAL_P/s=%d DROP_RX=%d DROP_TX=%d",
                    dpid,
                    stat.port_no,
                    rx_byte_rate,
                    tx_byte_rate,
                    rx_packet_rate,
                    tx_packet_rate,
                    total_byte_rate,
                    total_packet_rate,
                    stat.rx_dropped,
                    stat.tx_dropped
                )

            self.port_stats_prev[key] = {
                "rx_bytes": current_rx_bytes,
                "tx_bytes": current_tx_bytes,
                "rx_packets": current_rx_packets,
                "tx_packets": current_tx_packets
            }

