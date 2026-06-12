
class FlowMitigator:

    def __init__(self):
        self.blocked = set()

    def block(self, datapath, ip):

        if ip in self.blocked:
            return

        self.blocked.add(ip)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip
        )

        # drop rule (no actions)
        actions = []

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=inst
        )

        datapath.send_msg(mod)

        print(f"[MITIGATION] Blocked IP: {ip}")
