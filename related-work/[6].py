from scapy.all import *
import math
from scapy.all import PcapReader
from collections import defaultdict

packets = []

def extract_packet_data(packet):
    try:

        src_ip = dst_ip = src_port = dst_port = timestamp = ""

        # packet.show()

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif SCTP in packet:
            src_port = packet[SCTP].sport
            dst_port = packet[SCTP].dport

        timestamp = str(packet.time)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "timestamp": timestamp,
        }
    except Exception as e:
        print(f"Error extracting packet data: {e}")


# def calculate_spd_per_ip(packets):
#     # Create dictionaries to keep track of source and destination flows for each IP
#     source_flows = defaultdict(int)
#     destination_flows = defaultdict(int)
#     spd_per_ip = {}

#     for packet in packets:
#         src_ip = packet["src_ip"]
#         dst_ip = packet["dst_ip"]

#         # Count source and destination flows for each IP
#         source_flows[src_ip] += 1
#         destination_flows[dst_ip] += 1

#     for ip in source_flows.keys():
#         spd = math.log(source_flows[ip] / destination_flows[ip])
#         spd_per_ip[ip] = spd

#     return spd_per_ip

# Define a function to calculate SPD (Source per Destination)
def calculate_spd_for_ip(packets, ip):
    source_flows = 0
    destination_flows = 0

    for packet in packets:
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]

        if src_ip == ip:
            source_flows += 1

        if dst_ip == ip:
            destination_flows += 1

    if destination_flows == 0:
        return float("inf")  # Handle the case where the denominator is zero

    spd = math.log(source_flows / destination_flows)
    return spd



# Define a function to calculate PPI (Ports per IPs)
# def calculate_ppi(packets):
#     destination_ports = defaultdict(int)
#     destination_ip_addresses = defaultdict(int)
#     ppi_per_ip = {}

#     for packet in packets:
#         dst_ip = packet["dst_ip"]
#         dst_port = packet["dst_port"]

#         destination_ports[dst_ip] += 1
#         destination_ip_addresses[dst_ip] += 1

#     for ip in destination_ports.keys():
#         if destination_ip_addresses[ip] == 0:
#             ppi = float("inf")  # Handle the case where the denominator is zero
#         else:
#             ppi = math.log(destination_ports[ip] / destination_ip_addresses[ip])
#         ppi_per_ip[ip] = ppi

#     return ppi_per_ip


def calculate_ppi_for_ip(packets, ip):
    destination_ports = 0
    destination_ip_addresses = 0

    for packet in packets:
        dst_ip = packet["dst_ip"]
        dst_port = packet["dst_port"]

        if dst_ip == ip:
            destination_ports += 1
            destination_ip_addresses += 1

    if destination_ip_addresses == 0:
        ppi = float("inf")  # Handle the case where the denominator is zero
    else:
        ppi = math.log(destination_ports / destination_ip_addresses)

    return ppi


if __name__=="__main__":

    # Replace 'pcap_file' with the path to your pcap file
    pcap_file = '//home/khattak01/Desktop/thesis/tests/packets-500.pcap'


    # Open the pcap file using PcapReader
    with PcapReader(pcap_file) as pcap_reader:
        # Loop through packets
        for packet in pcap_reader:

            packet = extract_packet_data(packet)
            packets.append(packet)

            print(packet)
            print(len(packets))

