class FlowMitigator:

    def __init__(self, timeout=60):
        self.timeout = timeout

    def block(self, datapath, ip):

        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=500,
            hard_timeout=self.timeout,
            match=match,
            instructions=[]
        )

        datapath.send_msg(mod)
