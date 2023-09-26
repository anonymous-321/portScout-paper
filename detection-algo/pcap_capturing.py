import dpkt
import socket
from typing import Iterator

def process_packet(packet):
    eth = dpkt.ethernet.Ethernet(packet)
    if isinstance(eth.data, dpkt.ip.IP) and (isinstance(eth.data.data, dpkt.tcp.TCP) or isinstance(eth.data.data, dpkt.udp.UDP)):
        ip_packet = eth.data
        src_ip = socket.inet_ntoa(ip_packet.src)
        dst_ip = socket.inet_ntoa(ip_packet.dst)

        if isinstance(ip_packet.data, dpkt.tcp.TCP):
            transport_protocol = "TCP"
            tcp_packet = ip_packet.data
            src_port = tcp_packet.sport
            dst_port = tcp_packet.dport
            flags = tcp_packet.flags
        elif isinstance(ip_packet.data, dpkt.udp.UDP):
            transport_protocol = "UDP"
            udp_packet = ip_packet.data
            src_port = udp_packet.sport
            dst_port = udp_packet.dport
            flags = "N/A"

        timestamp = dpkt.timestamp(pkt, return_micros=True)

        # Call your function here with the extracted information
        print_packet_info(src_ip, dst_ip, src_port, dst_port, transport_protocol, flags, timestamp)

def print_packet_info(src_ip, dst_ip, src_port, dst_port, transport_protocol, flags, timestamp):
    print("Source IP:", src_ip)
    print("Destination IP:", dst_ip)
    print("Source Port:", src_port)
    print("Destination Port:", dst_port)
    print("Transport Protocol:", transport_protocol)
    print("Flags:", flags)
    print("Timestamp:", timestamp)
    print("-------------------------------------------------------")

class PacketSniffer:
    def __init__(self):
        """Monitor a network interface for incoming data, decode it and
        send it to pre-defined output methods.
        """
        self._observers = list()

    def register(self, observer) -> None:
        """Register an observer for processing/output of decoded frames.

        :param observer: Any object that implements the interface
        defined by the Output abstract base-class.
        """
        self._observers.append(observer)

    def _notify_all(self, *args, **kwargs) -> None:
        """Send a decoded frame to all registered observers for further
        processing/output."""
        [observer.update(*args, **kwargs) for observer in self._observers]

    def listen(self, interface: str) -> Iterator:
        """Directly output a captured Ethernet frame while
        simultaneously notifying all registered observers, if any.

        :param interface: Interface from which a given frame will be
            captured and decoded.
        """
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) as sock:
            sock.bind((interface, 0))
            for _ in range(100000):  # Replace this with the desired number of packets
                raw_data, _ = sock.recvfrom(65535)  # Max packet size
                yield raw_data

if __name__ == "__main__":
    sniffer = PacketSniffer()

    class Observer:
        def update(self, frame):
            process_packet(frame)

    sniffer.register(Observer())

    # Replace 'eth0' with the network interface you want to sniff on
    sniffer.listen('wlp0s20f3')
        # print(frame)
