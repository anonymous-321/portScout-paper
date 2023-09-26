import concurrent.futures
from scapy.all import sniff

# scan_count = 0
def check_ports_packets(packets):
    dst_ports = []

    for packet in packets:
      packet_port = packet.split('_')[3]
      if not len(dst_ports):
        dst_ports.append({'port':packet_port,'packets':[packet]})
      else:
        for i in range(len(dst_ports)):
          if dst_ports[i]['port'] == packet_port:
            t = dst_ports[i]['packets']
            t.append(packet)
            dst_ports[i] = t

    return dst_ports

list = ['192.168.94.237_64.233.184.188_5228_5228_TCP_A_1690138299.781521', '64.233.184.188_192.168.94.237_5228_5228_TCP_A_1690138300.043239', '192.168.94.237_224.0.0.251_5353_5353_UDP_0_1690138303.646697', '192.168.94.237_35.186.194.58_58924_443_TCP_A_1690138313.94534', '192.168.94.237_13.67.9.5_55438_443_TCP_A_1690138313.946552', '192.168.94.237_13.67.9.5_55450_443_TCP_A_1690138313.94865', '35.186.194.58_192.168.94.237_443_58924_TCP_A_1690138314.012793', '192.168.94.237_18.64.141.49_40446_443_TCP_A_1690138314.01628', '18.64.141.49_192.168.94.237_443_40446_TCP_A_1690138314.085244', '13.67.9.5_192.168.94.237_443_55450_TCP_A_1690138314.088617', '13.67.9.5_192.168.94.237_443_55450_TCP_A_1690138314.206569']
# print(check_ports_packets(list))
import threading
count = 0
# Function to process a single packet (Replace this with your actual processing logic)
def process_packet(packet):
    pass
    # print(f"Processing packet: {packet.summary()}")
# Callback function to process a packet using the ThreadPoolExecutor
def process_packet_callback(packet):
    global count
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        # Submit the packet to the ThreadPoolExecutor for asynchronous processing
        executor.submit(process_packet, packet)
    
    # Get the number of threads running in the current program
    # num_threads = threading.active_count()
    count +=1
    # print("Number of threads running:", num_threads)
    print(count)

# Function to start sniffing traffic and call the callback function for each packet
def start_sniffing(interface):
    # Start sniffing packets on the specified interface
    sniff(filter="dst host 192.168.18.126 and (tcp or udp)",prn=process_packet_callback, iface=interface)

# Main function to run the program
def main():
    # Replace "eth0" with the name of the network interface you want to sniff
    network_interface = "wlp0s20f3"

    # Start sniffing traffic and processing packets using the callback function
    start_sniffing(network_interface)

if __name__ == "__main__":
    main()


from scapy.all import sniff

count = 0

# Function to process a single packet (Replace this with your actual processing logic)
def process_packet(packet):
    global count
    # print(f"Processing packet: {packet.summary()}")
    tmp = []
    for i in range(10000):
        tmp.append(i)
    count += 1
    print(count)

# Function to start sniffing traffic and process each packet
def start_sniffing(interface):
    # Start sniffing packets on the specified interface
    sniff(filter="ip host 192.168.18.51 and (tcp or udp)",store=0, prn=process_packet, iface=interface)

# Main function to run the program
def main():
    # Replace "eth0" with the name of the network interface you want to sniff
    network_interface = "wlp0s20f3"

    # Start sniffing traffic and processing packets using the process_packet function
    start_sniffing(network_interface)

# if __name__ == "__main__":
#     main()
