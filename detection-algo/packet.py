from util import get_time


class Packet:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, packet_type):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.packet_type = packet_type
        self.timestamp = get_time()
    def data(self):
        return f"{self.src_ip}_{self.dst_ip}_{self.src_port}_{self.dst_port}_{self.packet_type}_{self.timestamp}"
