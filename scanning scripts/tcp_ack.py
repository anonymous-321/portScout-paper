from scapy.all import *

import random

port_range = range(1024, 49152)

def tcp_ack(target_ip, target_port):
    try:
        # Generate a random source port from the defined range.
        # source_port = random.choice(port_range)
        source_port = 24

        # Craft a TCP packet with only the ACK flag set (ACK scan)
        tcp_packet = IP(dst=target_ip) / TCP(sport=source_port,dport=target_port, flags="A")

        # Send the ACK scan packet and receive the response
        response = sr1(tcp_packet, timeout=2, verbose=0)

        # Check the response
        if response is not None:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x14:  # RST-ACK (port closed)
                    print(f"Port {target_port} is unfiltered and closed")
                elif response[TCP].flags == 0x04:  # RST (port is filtered)
                    print(f"Port {target_port} is closed")
                else:
                    pass
                    # print(f"Port {target_port} state is open")
            else:
                pass
                # print(f"Port {target_port} state is unknown")
        else:
            pass
            # print(f"Port {target_port} is open/filtered")

    except KeyboardInterrupt:
        print("Scan aborted.")
    except Exception as e:
        print(f"Error: {str(e)}")

