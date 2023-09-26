from scapy.all import TCP,IP, sr1

#SYN scan is the most popular scan option for good reason. It can be performed quickly, 
# scanning thousands of ports per second on a fast network not hampered by intrusive firewalls. 
# SYN scan is relatively unobtrusive and stealthy, since it never completes TCP connections. 
def tcp_syn(target_ip, target_port):
    try:
        # Craft a TCP SYN packet
        syn_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")

        # Send the packet and receive the response
        response = sr1(syn_packet, timeout=1, verbose=0)

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