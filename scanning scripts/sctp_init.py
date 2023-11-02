from scapy.all import *

import random

port_range = range(1024, 49152)


def sctp_init(target_ip, target_port):
    try:

        # source_port = random.choice(port_range)
        source_port = 1234
        # Craft an SCTP INIT packet for the connection attempt
        sctp_init_packet = IP(dst=target_ip) / SCTP(sport=source_port,dport=target_port)

        # Send the SCTP INIT packet and receive the response
        response, _ = sr(sctp_init_packet, timeout=1, verbose=0)

        # Check the response
        for packet in response:
            if SCTPChunk_INIT_ACK in packet:
                print(f"Port {target_port} is open (SCTP INIT ACK received)")

        # print(f"Port {target_port} is closed or filtered")

    except KeyboardInterrupt:
        print("Scan aborted.")
    except Exception as e:
        print(f"Error: {str(e)}")