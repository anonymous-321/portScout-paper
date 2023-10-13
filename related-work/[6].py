from scapy.all import *
import math

from scapy.all import *

def extract_packet_data(raw_packet):
    try:
        packet = Ether(raw_packet)  # Assuming it's an Ethernet packet, adjust as needed

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = str(packet.time)

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            # protocol = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            # protocol = "TCP"
        elif SCTP in packet:
            src_port = packet[SCTP].sport
            dst_port = packet[SCTP].dport
            # protocol = "SCTP"
        else:
            # Handle other protocols as needed
            src_port = 0
            dst_port = 0
            # protocol = "Unknown"

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            # "protocol": protocol,
            "timestamp": timestamp,
        }
    except Exception as e:
        print(f"Error extracting packet data: {e}")
        return {}


# Define a function to calculate PPI (Ports per IPs)
def calculate_ppi(src_ports, dst_ip):
    try:
        ppi = math.log(src_ports / dst_ip)
        return ppi
    except Exception as e:
        print(f"Error calculating PPI: {e}")
        return 0

# Define a function to calculate SPD (Source per Destination)
def calculate_spd(src_ip, dst_ip):
    try:
        spd = math.log(src_ip / dst_ip)
        return spd
    except Exception as e:
        print(f"Error calculating SPD: {e}")
        return 0

def main(pkt):
    packet = extract_packet_data(pkt)

