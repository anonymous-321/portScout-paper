from scapy.all import IP, TCP, send,sr1
import random

# Define the list of decoy IP addresses
decoy_ips = ["192.168.18.21", "192.168.18.141", "192.168.18.29","192.168.18.48", "192.168.18.53"]

# Define a range for random ports (e.g., 1024-49151).
port_range = range(1024, 49152)

# Craft decoy scanning packets
def decoy_scanning(target_ip, target_port):
    try:
        for source_ip in decoy_ips:
            
            # Generate a random source port from the defined range.
            # source_port = random.choice(port_range)
            source_port = 125
            # Craft a TCP SYN packet
            syn_packet = IP(src=source_ip,dst=target_ip) / TCP(sport=source_port,dport=target_port, flags="S")

            # Send the packet and receive the response
            response = sr1(syn_packet, timeout=.5, verbose=0)

            # Check the response
            if response is not None and response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN/ACK packet
                    print(f"Port {target_port} is open")
    except KeyboardInterrupt:
        print("Scan aborted.")
    except Exception as e:
        print(f"Error: {str(e)}")

