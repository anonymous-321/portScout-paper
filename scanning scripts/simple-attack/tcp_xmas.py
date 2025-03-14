from scapy.all import *

import random

port_range = range(1024, 49152)

def tcp_xmas(target_ip, target_port):
    try:

       # Generate a random source port from the defined range.
        # source_port = random.choice(port_range)
        source_port = 50

        # Craft a TCP packet with the FIN, URG, and PSH flags set (XMAS scan)
        tcp_packet = IP(dst=target_ip) / TCP(sport=source_port,dport=target_port, flags="FPU")

        # Send the XMAS scan packet and receive the response
        response = sr1(tcp_packet, timeout=1, verbose=0)

        # Check the response
        if response is not None:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x14:  # RST-ACK (port closed)
                    pass
                    # print(f"Port {target_port} is closed")
                elif response[TCP].flags == 0x04:  # RST (port is open)
                    print(f"Port {target_port} is unknown")
                else:
                    pass
                    # print(f"Port {target_port} state is Open")
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
