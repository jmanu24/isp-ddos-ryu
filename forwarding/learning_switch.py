from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp


class LearningSwitch:

    def __init__(self):

        self.mac_to_port = {}

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        buffer_id=None,
        idle_timeout=0,
        hard_timeout=0):

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
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            buffer_id=buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER
        )

        datapath.send_msg(mod)

    def switch_features_handler(self, datapath):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(
            datapath,
            priority=0,
            match=match,
            actions=actions,
            idle_timeout=0,
            hard_timeout=0
        )

        print(
            f"INSTALANDO TABLE MISS EN {datapath.id}"
        )

    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        if out_port == ofproto.OFPP_FLOOD:

            data = None

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data
            )

            datapath.send_msg(out)
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:

            match_fields = {
                "eth_type": 0x0800,
                "ipv4_src": ip_pkt.src,
                "ipv4_dst": ip_pkt.dst,
                "ip_proto": ip_pkt.proto
            }

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            if tcp_pkt:

                match_fields["tcp_src"] = tcp_pkt.src_port
                match_fields["tcp_dst"] = tcp_pkt.dst_port

            elif udp_pkt:

                match_fields["udp_src"] = udp_pkt.src_port
                match_fields["udp_dst"] = udp_pkt.dst_port

            match = parser.OFPMatch(
                **match_fields
            )

            print(
                f"L3/L4 FLOW {ip_pkt.src} -> {ip_pkt.dst} proto={ip_pkt.proto}"
            )

        else:

            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip,
                ip_proto=ip_proto
            )

        self.add_flow(
            datapath,
            priority=10,
            match=match,
            actions=actions,
            idle_timeout=60,
            hard_timeout=0
        )

        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)