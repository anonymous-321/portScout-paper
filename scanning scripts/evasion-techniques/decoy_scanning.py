from scapy.all import IP, TCP, send
import random

# Define the target IP address and port number
target_ip = "TARGET_IP_ADDRESS"
target_port = 80

# Define the list of decoy IP addresses
decoy_ips = ["DECOY_IP_ADDRESS_1", "DECOY_IP_ADDRESS_2", "DECOY_IP_ADDRESS_3"]

# Craft decoy scanning packets
def decoy_scanning(target_ip, target_port):
    for ip in range(decoy_ips):
        
        # Craft IP and TCP headers with decoy and target IP addresses
        ip_packet = IP(src=ip, dst=target_ip)
        tcp_packet = TCP(dport=target_port, flags="S")
        
        # Send the packet with both genuine and fake IP addresses
        packet = ip_packet / tcp_packet
        send(packet, verbose=False)

