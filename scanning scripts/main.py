from tcp_syn import tcp_syn
from tcp_connect import tcp_connect
from udp_scan import udp_scan
from sctp_init import sctp_init
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


target_ip = '192.168.18.179'

def scan_port(port):
    tcp_syn(target_ip, port)
    # tcp_connect(target_ip, port)
    # udp_scan(target_ip, port)
    # sctp_init(target_ip, port)
    # tcp_null(target_ip,port)
    # tcp_fin(target_ip,port)
    # tcp_xmas(target_ip,port)
    # tcp_ack(target_ip,port)
    # tcp_maimon(target_ip,port)
    # tcp_custom_scan(target_ip,port)
    


if __name__ == "__main__":

    # print(len(top_tcp_ports))
    # print(len(top_udp_ports))
    
    max_threads = 5  # Maximum number of threads

    with ThreadPoolExecutor(max_threads) as executor:
        executor.map(scan_port, nmap_top_tcp_ports)

    # max_threads = 5  # Maximum number of threads
    # port_range_start = 1000
    # port_range_end = 6000  # Adjust the end port as needed

    # for i in range(port_range_start,port_range_end+1):
    #     scan_port(i)

    # with ThreadPoolExecutor(max_threads) as executor:
    #     executor.submit(scan_port, port_range_start, port_range_end)
    

    # with ThreadPoolExecutor(max_threads) as executor:
    #     executor.map(scan_port, top_udp_ports)