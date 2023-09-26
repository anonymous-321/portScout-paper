from scapy.all import *

def tcp_custom_scan(target_ip, target_port):
    try:
        # Craft a TCP packet with arbitrary flag combinations
        tcp_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="FSRPAU")

        # Send the Maimon Scan packet and receive the response
        response = sr1(tcp_packet, timeout=2, verbose=0)

        # Check the response
        if response is not None:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x14:
                    pass
                elif response[TCP].flags == 0x12: 
                    pass
                else:
                    pass
            else:
                pass
        else:
            pass

    except KeyboardInterrupt:
        print("Scan aborted.")
    except Exception as e:
        print(f"Error: {str(e)}")
