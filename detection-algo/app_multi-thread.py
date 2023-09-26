# from scapy.all import *
import sys
import threading
import time
import concurrent.futures


from scapy.layers.inet import IP, TCP, UDP
from scapy.all import sniff

# from packet import Packet
from util import get_time


PORT_THRESHOLD = 15
TIME_THRESHOLD = 30
DELETE_TIME_THRESHOLD = 60

# Create a list to store packet data
packets = []
scanner_packets = {}
# scan_count = 0

# Define a lock to synchronize access to the 'packets' list
packets_lock = threading.Lock()

#This function inserts a packet into the packets list while ensuring thread safety with the help of the packets_lock mutex.
def insert_packet(packet):
    """
    Inserts the given packet into the 'packets' list.

    :param packet: The packet to be inserted into the list.
    """

    with packets_lock:
        packets.append(packet)

#This function is used to delete a packet from the packets list if it exceeds the DELETE_TIME_THRESHOLD (in seconds) based on the packet's timestamp.
#The packet timestamp is extracted from the packet string, which is in the format "src_ip_dst_ip_src_port_dst_port_packet_type_flags_timestamp".
def delete_packet(packet):

    """
    Deletes the given packet from the 'packets' list if its timestamp difference is greater than the DELETE_TIME_THRESHOLD.

    :param packet: The packet to be deleted from the list.
    """

    # print(packet)
    diff = int(get_time() - float(packets.split('_')[-1]))
    # print(diff)
    if diff > DELETE_TIME_THRESHOLD:
            # delete_packet(i)
        with packets_lock:
            packets.remove(packet)


# ThreadPoolExecutor with 20 worker threads
executor_20 = concurrent.futures.ThreadPoolExecutor(max_workers=20)
#This function calls delete_packet(packet) for each item in the packets list concurrently using a ThreadPoolExecutor with 20 worker threads.
#It helps to remove old packets that have exceeded the DELETE_TIME_THRESHOLD.
def remove_entries():
    """
    Removes packets from the 'packets' list
    """

    # print("------------remove_entries------------")
    if not len(packets):
        return
    
    # Submit tasks to the executor for each item in the list
    futures = [executor_20.submit(delete_packet, item) for item in packets]

    # # Wait for all tasks to complete
    concurrent.futures.wait(futures)

    # Shutdown the executor after completing the tasks
    # executor_20.shutdown(wait=True)

    # print("Removing entries...")

#This function is used to save packet data from potential scanners. It extracts the source IP from the packet string and stores it in the scanner_packets dictionary.
#The scanner_packets dictionary has IP addresses as keys and lists of packets as values.
def save_scanner_data(packet):
    """
    Saves the packet in the scanner_packets dictionary based on its source IP address.

    :param packet: The packet to be saved in the scanner_packets dictionary.
    """

    ip = packet.split('_')[0]
    if not scanner_packets:
        scanner_packets[ip] = [packet]

    elif ip in scanner_packets:
        tmp = []
        tmp = scanner_packets.get(ip)
        tmp.append(packet)
        scanner_packets[ip] = tmp
    else:
        scanner_packets[ip] = [packet]

# global dst_ports
dst_ports = []
#This function checks for packets with the same destination port and groups them together based on the port number in the dst_ports list.
#If the number of packets with the same destination port exceeds the PORT_THRESHOLD, it triggers a scanning alert and moves the packets to scanner_packets.
def check_ports_packets(packet):

    """
    Checks the destination ports in packets and groups them based on port numbers in the 'dst_ports' list.
    If the number of packets for a port exceeds PORT_THRESHOLD, it triggers a scanning alert.

    :param packet: The packet to be checked for destination ports.
    """

    global dst_ports

    # for packet in packets:
    packet_port = packet.split('_')[3]
    if not len(dst_ports):
        with packets_lock:
            dst_ports.append({'port': packet_port, 'packets': [packet]})
        # break
    else:
        # print(dst_ports)
        tmp = True
        for i in range(len(dst_ports)):
            t = []
            if dst_ports[i]['port'] == packet_port:
                t = dst_ports[i]['packets']
                t.append(packet)
                # with packets_lock:
                dst_ports[i]['packets'] = t
                tmp = False
                break

        if tmp:
            with packets_lock:
                dst_ports.append({'port': packet_port, 'packets': [packet]})
            # break
    
    if len(dst_ports) > PORT_THRESHOLD:
        # print("True")
        # tmp = True
        port_data = set()
        for port in dst_ports:
            # if not tmp:
            #     break
            # tmp_list = []
            tmp_flg = True
            for p_p in port['packets']:
                timestamp = float(p_p.split('_')[-1])
                current_time = get_time()
                time_diff = int(get_time() - timestamp)
                # print("time - diff",time_diff)
                if time_diff < TIME_THRESHOLD:
                    # tmp_list.append()
                    if tmp_flg:
                        port_data.add(port['port'])
                        tmp_flg = False
                    with packets_lock:
                        save_scanner_data(p_p) 
                        packets.remove(p_p)
            # print(len(port_data))
            if len(port_data)>PORT_THRESHOLD:
                # print(len(port))
                # with packets_lock:
                    # global scan_count 
                    # scan_count = scan_count + 1
                # print("--------------------------------------------------------",dst_ports,"--------------------------------------------------------")
                
                print("Scanning Alert")
    # print(dst_ports)               
    # print(len(dst_ports))               
    # return dst_ports


# ThreadPoolExecutor with 60 worker threads
executor_60 = concurrent.futures.ThreadPoolExecutor(max_workers=60)
#This function calls check_ports_packets(packet) for each item in the packets list concurrently using a ThreadPoolExecutor with 60 worker threads.
#It helps to check for possible scanning activity based on the number of packets with the same destination port.
def check_conditions():


    global dst_ports
    dst_ports = []
    # print("------------check_conditions------------")
    if not len(packets):
        return
    
    # Submit tasks to the executor for each item in the list
    futures = [executor_60.submit(check_ports_packets, packet) for packet in packets]

    # Wait for all tasks to complete
    concurrent.futures.wait(futures)


#This function processes the captured packet, extracting header information for TCP and UDP packets with the IP layer.
#It constructs a packet string in the format "src_ip_dst_ip_src_port_dst_port_packet_type_flags_timestamp" and inserts it into the packets list.
#Additionally, it calls check_conditions() and remove_entries() to handle possible scanning activity and remove old packets, respectively.
def process_packet(packet):
    """
    Process the captured packet and extract header information for TCP and UDP packets with the IP layer.
    :param packet: The captured packet to be processed.

    """


    if packet.haslayer(IP):
        ip_packet = packet[IP]

        if packet.haslayer(TCP):
            tcp_packet = packet[TCP]
            packet_type = "TCP"
            flags = tcp_packet.flags
            src_port = tcp_packet.sport
            dst_port = tcp_packet.dport

        elif packet.haslayer(UDP):
            udp_packet = packet[UDP]
            packet_type = "UDP"
            flags = "0"
            dst_port = udp_packet.dport
            src_port = udp_packet.sport

        else:
            dst_port = 0
            src_port = 0

        src_ip = ip_packet.src
        dst_ip = ip_packet.dst
        
        try:
            packet = f"{src_ip}_{dst_ip}_{src_port}_{dst_port}_{packet_type}_{flags}_{get_time()}"
            # print({'condition':False,'data':packet})
            insert_packet(packet)
            # print("----------------------------------------------")
        except:
            print("Error storing the packet _-_")
        # print(f"Packet Type: {packet_type}")
        # print(f"Flags: {flags}")
        # print(f"Packet type : {packet_type}")
        # print(f"Source IP: {src_ip}")
        # print(f"Destination IP: {dst_ip}")
        # print(f"Source Port: {src_port}")
        # print(f"Destination Port: {dst_port}\n")
    # print("----------------------------------------------")

    # size_in_bytes = sys.getsizeof(packets)
    # size_in_mbs = size_in_bytes / (1024 * 1024)

    # print(f"Size of the list: {size_in_mbs} MB")
    # print("----------------------------------------------\n")
    # print("packets len ", len(packets))

    # Get the number of threads running in the current program
    # num_threads = threading.active_count()

    # print("Number of threads running:", num_threads)
    # check_conditions()
    # remove_entries()

# Define a function for packet sniffing
def packet_sniffer():
    # Define the network interface to capture traffic from
    interface = "wlp0s20f3"
    # When store is set to 0, it means that the captured packets will not be stored in memory. Instead, 
    # they will be processed by the callback function (prn) immediately as they are captured. This is 
    # useful when dealing with a large number of packets or when memory usage needs to be minimized.
    sniff(filter="dst host 192.168.18.126 and (tcp or udp)", prn=process_packet, store=0,iface=interface)
    # sniff(filter="tcp or udp", prn=process_packet, store=0,iface=interface)


#This function is responsible for periodically calling remove_entries() and check_conditions() functions with a 2-second interval using separate threads.
#It ensures the removal of old packets and checks for scanning activity at regular intervals.
def periodic_remove_entries():

    while True:
        periodic_remove_entries_thread = threading.Thread(target=remove_entries)
        periodic_remove_entries_thread.start()
        # remove_entries()
        periodic_check_condition_thread = threading.Thread(target=check_conditions)
        periodic_check_condition_thread.start()
        time.sleep(2)
        # check_conditions()

if __name__ == "__main__":
    
    """
    Entry point of the program. It starts the packet sniffer and the periodic removal of entries and checks conditions.

    Instructions:
    1. The program captures packets using the specified network interface ('wlp0s20f3').
    2. Captured packets are processed using the process_packet() function.
    3. The remove_entries() function is periodically called to manage the 'packets' list.
    4. The check_conditions() function is also periodically called to manage the 'scanner_packets' dictionary.
    5. To stop the packet capturing process, press Ctrl+C.

    Note: Before running the program, ensure the 'scapy' and 'concurrent.futures' modules are installed.
    """

    # Print a start message
    print("Packet capturing started...")

    # Provide some instructions to the user.
    print("Sniffing will continue until this program is interrupted.")
    print("To stop sniffing, press Ctrl+C.")

    try:
        # Create and start the packet sniffing thread
        sniffer_thread = threading.Thread(target=packet_sniffer)
        sniffer_thread.start()
        
        # Start the initial execution of remove_entries
        periodic_remove_entries()

    except KeyboardInterrupt:
        print("\nInterrupt received! Stopping network sniffing...")

        print("The program has been closed.")