class FlowEvent:

    def __init__(self,
                 src_ip,
                 dst_ip,
                 protocol,
                 packets,
                 bytes,
                 flow_id):

        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.packets = packets
        self.bytes = bytes
        self.flow_id = flow_id
