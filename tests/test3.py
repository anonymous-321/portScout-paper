import sys
from scapy.all import *

# Target IP address
target_ip = "192.168.18.179"

# Define a range of ports to scan (adjust as needed)
start_port = 1
end_port = 100

# Create an IP packet with a TCP layer for the SYN scan
ip_packet = IP(dst=target_ip)

# Loop through the range of ports
for port in range(start_port, end_port + 1):
    # Create a TCP layer with the SYN flag set
    tcp_packet = TCP(sport=12345, dport=port, flags="S")
    
    # Combine the IP and TCP layers to create the packet
    packet = ip_packet / tcp_packet
    
    # Send the packet and receive a response (adjust timeout as needed)
    response = sr1(packet, timeout=1, verbose=0)
    
    # Check if a response was received
    if response is not None:
        # Check the TCP flags in the response packet
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"Port {port} is open")
    
# Close the program
sys.exit(0)
