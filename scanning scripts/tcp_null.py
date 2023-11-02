from scapy.all import *
import random

port_range = range(1024, 49152)


def tcp_null(target_ip, target_port):
    try:
        
        # Generate a random source port from the defined range.
        # source_port = random.choice(port_range)
        source_port = 1111
        # Craft a TCP packet with no flags set (null scan)
        tcp_packet = IP(dst=target_ip) / TCP(sport=source_port,dport=target_port, flags="")

        # Send the null scan packet and receive the response
        response = sr1(tcp_packet, timeout=1, verbose=0)

        # Check the response
        if response is not None:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x14:  # RST-ACK (port closed)
                    # print(f"Port {target_port} is closed")
                    pass
                elif response[TCP].flags == 0x04:  # RST (port is unknown)
                    print(f"Port {target_port} is unknown")
                else:
                    print(f"Port {target_port} state is Open")# if return nothing the port is open
            else:
                print(f"Port {target_port} state is unknown")
        else:
            # print(f"Port {target_port} is open/filtered")
            pass

    except KeyboardInterrupt:
        print("Scan aborted.")
    except Exception as e:
        print(f"Error: {str(e)}")
