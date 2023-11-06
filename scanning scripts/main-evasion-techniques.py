from tcp_syn import tcp_syn
from tcp_connect import tcp_connect
from tcp_null import tcp_null
from tcp_fin import tcp_fin
from tcp_xmas import tcp_xmas
from tcp_ack import tcp_ack
from tcp_maimon import tcp_maimon
from tcp_custom_scan import tcp_custom_scan

from nmap_top_ports import nmap_top_tcp_ports
from top_ports import top_tcp_ports
from top_ports import top_udp_ports

from concurrent.futures import ThreadPoolExecutor

#from mixture_tehnique_scan import random_scan_function
#from distributed_scanning import distributed_scan
#from packet_manipulation import packet_manipulation
from decoy_scanning import decoy_scanning

from nmap_top_ports import nmap_top_tcp_ports
from top_ports import top_tcp_ports
from top_ports import top_udp_ports

from concurrent.futures import ThreadPoolExecutor
import random

target_ip = '192.168.18.179'

def scan_port(port):
    # print("port >>> ", port)
    # random_scan_function(target_ip,port)
    #packet_manipulation(target_ip,port)
    decoy_scanning(target_ip,port)
    # print("-----------------------------------------")

if __name__ == "__main__":

    # print(len(top_tcp_ports))
    # print(len(top_udp_ports))
    
    max_threads = 80  # Maximum number of threads

    # Randomly select 198 ports
    random_ports = set(random.sample(top_tcp_ports, 796))
    random_ports.add(1111)
    # random_ports.add(777)
    random_ports.add(1234)
    # random_ports.add(5000)
    # random_ports.add(3000)

    with ThreadPoolExecutor(max_threads) as executor:
        executor.map(scan_port, random_ports)