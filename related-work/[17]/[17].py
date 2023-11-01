from scapy.all import PcapReader
from scapy.all import *


packets = []

# Define the format_packet_data function
def extract_packet_data(packet):
    try:
        src_ip = dst_ip = tcp_flags = ""
        protocol = "Unknown"
        # packet.show()

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            tcp_flags = packet[TCP].sprintf('%flags%')

        
        timestamp = float(packet.time)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol":protocol,
            "tcp_flags":tcp_flags,
            "timestamp": timestamp,
        }   
    
    except Exception as e:
        print(f"Error extracting packet data: {e}")


def process_packet(packet):
    packet = extract_packet_data(packet)
    print(packet)
    print("----------------------------------------------------------")

if __name__ == "__main__":


    # Replace 'pcap_file' with the path to your pcap file
    pcap_file = '/home/khattak01/Desktop/thesis/tests/packets-500.pcap'

    packets_list = []

    # Open the pcap file using PcapReader
    with PcapReader(pcap_file) as pcap_reader:
        # Loop through packets
        for packet in pcap_reader:
            process_packet(packet)

    