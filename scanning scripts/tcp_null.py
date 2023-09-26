from scapy.all import *

def tcp_null(target_ip, target_port):
    try:
        # Craft a TCP packet with no flags set (null scan)
        tcp_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="")

        # Send the null scan packet and receive the response
        response = sr1(tcp_packet, timeout=1, verbose=0)

        # Check the response
        if response is not None:
            if response.haslayer(TCP):
                if target_port==5000 or 5001:
                    print(response)
                if response[TCP].flags == 0x14:  # RST-ACK (port closed)
                    # print(f"Port {target_port} is closed")
                    pass
                elif response[TCP].flags == 0x04:  # RST (port is open)
                    print(f"Port {target_port} is open")
                else:
                    print(f"Port {target_port} state is unknown")
            else:
                print(f"Port {target_port} state is unknown")
        else:
            # print(f"Port {target_port} is open/filtered")
            pass

    except KeyboardInterrupt:
        print("Scan aborted.")
    except Exception as e:
        print(f"Error: {str(e)}")
