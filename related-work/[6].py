from scapy.all import *
import math
from scapy.all import PcapReader
# from collections import defaultdict

packets = []

def extract_packet_data(packet):
    try:

        src_ip = dst_ip = src_port = dst_port = ""

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

        # timestamp = str(packet.time)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            # "timestamp": timestamp,
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

    spd = round(math.log(source_flows / destination_flows), 4)
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
    unique_dest_ips = set()
    unique_dest_ports = set()

    for packet in packets:
        if packet["src_ip"] == ip:
            unique_dest_ips.add(packet["dst_ip"])
            unique_dest_ports.add(packet["dst_port"])

    if unique_dest_ips == 0:
        ppi = float("inf")  # Handle the case where the denominator is zero
    else:
        ppi = round(math.log(len(unique_dest_ports) / len(unique_dest_ips)),4)

    return ppi

def check_area(ppi, spd):
    if ppi >= 4.0 and spd >= 4.0:
        # Red area: 4.0 ≤ PPI, 4.0 ≤ SPD
        # horizontal port scan attack
        return "Red area"
    elif ppi <= -4.0 and spd >= 4.0:
        # Green area: PPI ≤ -4.0, 4.0 ≤ SPD
        # vertical port scan attack
        return "Green area"
    elif ppi >= 4.0 and spd <= 2.0:
        # Yellow area: 4.0 ≤ PPI, SPD ≤ 2.0
        # benign 
        return "Yellow area"

    # None of the defined areas
    return "Undefined area"
    
if __name__=="__main__":

    # print(check_area(0.31,3))
    # Replace 'pcap_file' with the path to your pcap file
    pcap_file = '/home/khattak01/Desktop/thesis/tests/packets-500.pcap'


    # Open the pcap file using PcapReader
    with PcapReader(pcap_file) as pcap_reader:
        # Loop through packets
        for packet in pcap_reader:

            packet = extract_packet_data(packet)
            packets.append(packet)

            ppi = calculate_ppi_for_ip(packets, packet['src_ip'])
            sdp = calculate_spd_for_ip(packets,packet['src_ip'])

            print(ppi)        
            print(sdp)        
            print(packet)
            print(len(packets))
            #f rom paper, page 17 -> section results:5 -> 5.1 -> para 1
            # We defined that the red area is 4.0 ≤ PPI, 4.0 ≤ SPD, the green area is PPI ≤ −4.0, 4.0 ≤ SPD, and the yellow area is 4.0 ≤ PPI, SPD ≤ 2.0.
            res = check_area(ppi,sdp)
            print(res)
            print('---------------------------------------------------')

        # tmp = set()
        # for pkt in packets:
        #     tmp.add(pkt['src_port'])
        
        # print(len(tmp))

