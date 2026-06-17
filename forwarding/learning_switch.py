from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

class LearningSwitch:

    def __init__(self):
        self.mac_to_port = {}

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        buffer_id=None
    ):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        kwargs = {
            "datapath": datapath,
            "priority": priority,
            "match": match,
            "instructions": inst
        }

        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id

        mod = parser.OFPFlowMod(**kwargs)

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
            0,
            match,
            actions
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

        self.mac_to_port.setdefault(
            dpid,
            {}
        )

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:
            print(
                "IP DETECTADA",
                ip_pkt.src,
                "->",
                ip_pkt.dst,
                "PROTO",
                ip_pkt.proto
            )
        else:
            print("NO ES IP")

        eth = pkt.get_protocol(
            ethernet.ethernet
        )

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        if out_port != ofproto.OFPP_FLOOD:

            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst
            )

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:

                self.add_flow(
                    datapath,
                    1,
                    match,
                    actions,
                    msg.buffer_id
                )

                return

            self.add_flow(
                datapath,
                1,
                match,
                actions
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