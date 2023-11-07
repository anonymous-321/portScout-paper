from scapy.all import TCP,IP, sr1
import random


from nmap_top_ports import nmap_top_tcp_ports
from top_ports import top_tcp_ports

from concurrent.futures import ThreadPoolExecutor

# Define a range for random ports (e.g., 1024-49151).
port_range = range(1024, 49152)

#SYN scan is the most popular scan option for good reason. It can be performed quickly, 
# scanning thousands of ports per second on a fast network not hampered by intrusive firewalls. 
# SYN scan is relatively unobtrusive and stealthy, since it never completes TCP connections. 
def tcp_syn(target_ips, target_port):
    try:

        for ip in target_ips:
            # Generate a random source port from the defined range.
            source_port = random.choice(port_range)
            # source_port = 12345
            # Craft a TCP SYN packet
            syn_packet = IP(dst=ip) / TCP(sport=source_port,dport=target_port, flags="S")

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

target_ips = ['192.168.18.179','192.168.18.179','192.168.18.179','192.168.18.179','192.168.18.179']

def scan_port(port):
    # print("port >>> ", port)
    # random_scan_function(target_ip,port)
    #packet_manipulation(target_ip,port)
    #decoy_scanning(target_ip,port)
    tcp_syn(target_ips,port)
    print("-----------------------------------------")

if __name__ == "__main__":

    # print(len(top_tcp_ports))
    # print(len(top_udp_ports))
    
    max_threads = 80  # Maximum number of threads

    # Randomly select 198 ports
    random_ports = set(random.sample(top_tcp_ports,500))
    # random_ports.add(1111)
    # random_ports.add(777)
    # random_ports.add(1234)
    # random_ports.add(5000)
    # random_ports.add(3000)

    with ThreadPoolExecutor(max_threads) as executor:
        executor.map(scan_port, random_ports)