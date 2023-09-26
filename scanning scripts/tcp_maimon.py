from scapy.all import *

def tcp_maimon(target_ip, target_port):
    try:
        # Craft a TCP packet with FIN and ACK flags set (Maimon Scan)
        tcp_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="FA")

        # Send the Maimon Scan packet and receive the response
        response = sr1(tcp_packet, timeout=1, verbose=0)

        # Check the response
        if response is not None:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x14:  # RST-ACK (port closed)
                    pass
                    # print(f"Port {target_port} is closed")
                elif response[TCP].flags == 0x04:  # RST (port is open)
                    # print(f"Port {target_port} is closed")
                    pass
                else:
                    pass
                    # print(f"Port {target_port} state is unknown")
            else:
                pass
                # print(f"Port {target_port} state is unknown")
        else:
            pass
            print(f"Port {target_port} is open/filtered")

    except KeyboardInterrupt:
        print("Scan aborted.")
    except Exception as e:
        print(f"Error: {str(e)}")
