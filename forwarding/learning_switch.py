from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp


class LearningSwitch:

    def __init__(self, is_blocked=None, is_validated=None):

        self.mac_to_port = {}

        # Optional Callable[[dst_ip, dst_port, protocol], bool], queried
        # before installing a new IP forwarding rule. Lets the Orchestration
        # layer veto caching traffic toward a destination that's already
        # under an active distributed-attack block.
        self._is_blocked = is_blocked

        # Optional Callable[[dst_ip], bool], queried before installing an IP
        # forwarding rule. Until the destination has been through at least
        # one full detection cycle without triggering an attack, no rule —
        # permit or block — gets cached for it; packets are still forwarded,
        # just one at a time via packet-out, going through the controller
        # every time until validation completes.
        self._is_validated = is_validated

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

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        # ---------------------------------
        # EXTRAER IPv4
        # ---------------------------------

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # ---------------------------------
        # DESTINO BAJO BLOQUEO DISTRIBUIDO
        # ---------------------------------

        if ip_pkt and self._is_blocked:

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            if tcp_pkt:
                proto, dst_port = "TCP", tcp_pkt.dst_port
            elif udp_pkt:
                proto, dst_port = "UDP", udp_pkt.dst_port
            elif ip_pkt.proto == 1:
                proto, dst_port = "ICMP", 0
            else:
                proto, dst_port = "IP", 0

            if self._is_blocked(ip_pkt.dst, dst_port, proto):
                # Drop silently — no forwarding rule, no packet-out. The
                # destination already has an active distributed-attack
                # block; caching another per-source rule here would just
                # be a flow table entry that can never deliver traffic.
                return

        # ---------------------------------
        # INSTALAR FLOW
        # ---------------------------------

        if out_port != ofproto.OFPP_FLOOD:

            if ip_pkt:

                if self._is_validated is None or self._is_validated(ip_pkt.dst):

                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst
                    )

                    self.add_flow(
                        datapath,
                        priority=10,
                        match=match,
                        actions=actions,
                        idle_timeout=60,
                        hard_timeout=0
                    )

                # else: destination hasn't completed a clean detection
                # cycle yet — forward this packet only, cache nothing, so
                # every further packet keeps coming through the controller
                # until it's validated.

            else:

                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=dst,
                    eth_type=eth.ethertype
                )

                self.add_flow(
                    datapath,
                    priority=1,
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