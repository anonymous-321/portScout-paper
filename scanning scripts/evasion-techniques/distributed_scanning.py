from scapy.all import IP, TCP, sr1
import random

# Function to decide on the source port
def select_source_port():
    if random.choice([True, False]):  # Randomly choose between static and dynamic source port
        return random.randint(1024, 10000)  # Dynamic source port range
    else:
        return 8642  # Static source port


def distributed_scan(target_ip,target_port):
    # print("target_ip >>",target_ip)
    # print("port >>",port)
    # Generate a random source IP within the specified range
    try:

        source_ip = f"192.168.18.{random.randint(50, 99)}"
        # print("source_ip >>> ",source_ip)
        source_port = select_source_port()  # Decide the source port

        # Craft a TCP SYN packet
        syn_packet = IP(src=source_ip,dst=target_ip) / TCP(sport=source_port,dport=target_port, flags="S")

        # Send the packet and receive the response
        response = sr1(syn_packet, timeout=.5, verbose=0)

        # Check the response
        if response is not None and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN/ACK packet
                print(f"Port {target_port} is open")
                
            # elif response[TCP].flags == 0x14:  # RST/ACK packet (closed port)
            #     print(f"Port {target_port} is closed")
        # else:
            # print(f"Port {target_port} is filtered or did not respond")

    except KeyboardInterrupt:
        print("Scan aborted.")
    except Exception as e:
        print(f"Error: {str(e)}")
