from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

import time


class FlowStatsIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FlowStatsIDS, self).__init__(*args, **kwargs)

        self.datapaths = {}

        # store previous stats for delta calculation
        self.prev_stats = {}

        # thresholds (ajusta según tu red)
        self.byte_threshold = 1e6       # 1 MB entre intervalos
        self.packet_threshold = 1000

        self.monitor_thread = hub.spawn(self._monitor)

        self.logger.info("FlowStats IDS iniciado")

    # -------------------------------------------------
    # SWITCH CONNECTION
    # -------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        self.datapaths[datapath.id] = datapath

        self.logger.info("Switch conectado: %s", datapath.id)

    # -------------------------------------------------
    # MONITOR LOOP
    # -------------------------------------------------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
            hub.sleep(5)

    # -------------------------------------------------
    # REQUEST FLOW STATS
    # -------------------------------------------------
    def _request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # -------------------------------------------------
    # FLOW STATS REPLY HANDLER
    # -------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        total_bytes = 0
        total_packets = 0

        for stat in body:
            total_bytes += stat.byte_count
            total_packets += stat.packet_count

        prev = self.prev_stats.get(dpid, {
            "bytes": 0,
            "packets": 0,
            "time": time.time()
        })

        now = time.time()
        time_diff = now - prev["time"] if now - prev["time"] > 0 else 1

        # deltas
        byte_rate = (total_bytes - prev["bytes"]) / time_diff
        packet_rate = (total_packets - prev["packets"]) / time_diff

        self.logger.info(
            "SW %s | Byte/s: %.2f | Packet/s: %.2f",
            dpid, byte_rate, packet_rate
        )

        # -------------------------
        # IDS DETECTION LOGIC
        # -------------------------
        if byte_rate > self.byte_threshold or packet_rate > self.packet_threshold:
            self.logger.warning(
                "⚠ POSIBLE DDoS en switch %s | Byte/s=%.2f Packet/s=%.2f",
                dpid, byte_rate, packet_rate
            )

        # update snapshot
        self.prev_stats[dpid] = {
            "bytes": total_bytes,
            "packets": total_packets,
            "time": now
        }
