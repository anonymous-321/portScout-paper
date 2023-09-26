# from scapy.all import *
import sys
import threading

# Define a lock to synchronize access to the 'packets' list

from scapy.layers.inet import IP, TCP, UDP
from scapy.all import sniff

# from packet import Packet
from util import get_time


PORT_THRESHOLD = 100
TIME_THRESHOLD = 10
DELETE_TIME_THRESHOLD = 15

# packets_lock = threading.Lock()
# Create a hash table to store packet data
packets = []
deleted_packets = []

# Define a lock to synchronize access to the 'packets' list
packets_lock = threading.Lock()

# Function to insert a packet into the hash table
def insert_packet(packet):
    with packets_lock:
        packets.append(packet)

# Function to delete a packet from the 'packets' list
def delete_packet(packet_index):
    with packets_lock:
        deleted_packets.append(packets[packet_index])

        del packets[packet_index]
        print(f"Packet {packets[packet_index]} deleted after 15 seconds.")

def remove_entries():
    print(remove_entries)
    pass
    # current_time = get_time()
    # if not len(packets):
    #     return
        
    # for i in range (len(packets)):
    #     diff = int(current_time - float(packets[i]['data'].split('_')[-1]))
    #     print(diff)
    #     if not packets[i]["condition"] and diff > DELETE_TIME_THRESHOLD:
    #             delete_packet(i)
                # del packets[i]
                # print("Data deleted", packets[i])
    # packets = [packet for packet in packets if packet["condition"] or current_time - packet["timestamp"] <= 60]

def check_conditions():
    if not len(packets):
        return
    
    src_ports = set()
    dst_ports = set()

    for packet in packets:
        data = packet['data']
        if not packet['condition']:
            src_port = int(data.split('_')[2])
            dst_port = int(data.split('_')[3])
            src_ports.add(src_port)
            dst_ports.add(dst_port)

    if len(src_ports) > PORT_THRESHOLD or len(dst_ports) > PORT_THRESHOLD:
        for packet in packets:
            # if packet['condition']:
            #     continue

            timestamp = float(packet['data'].split('_')[-1])
            # current_time = get_time()
            time_diff = int(get_time() - timestamp)

            if time_diff < TIME_THRESHOLD:

                packet['condition'] = True
                print("Condition updated to True for entry:", packet)

def process_packet(packet):
    """
    Process the captured packet and extract header information for TCP and UDP packets with the IP layer.
    """
    if packet.haslayer(IP):
        ip_packet = packet[IP]

        if packet.haslayer(TCP):
            tcp_packet = packet[TCP]
            packet_type = packet.flags # As UDP packets do not have flags, I store the flag information in the packet type field for TCP packets and will store udp in packet type in case of udp packet
            # flags = tcp_packet.flags
            src_port = tcp_packet.sport
            dst_port = tcp_packet.dport

        elif packet.haslayer(UDP):
            udp_packet = packet[UDP]
            packet_type = "UDP"

            dst_port = udp_packet.dport
            src_port = udp_packet.sport
            # flags = None
        else:
            dst_port = 0
            src_port = 0

        src_ip = ip_packet.src
        dst_ip = ip_packet.dst
        
        try:
            packet = f"{src_ip}_{dst_ip}_{src_port}_{dst_port}_{packet_type}_{get_time()}"
            # print({'condition':False,'data':packet})
            insert_packet({'condition':False,'data':packet})
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
    print("----------------------------------------------")
    print(len(packets))

    size_in_bytes = sys.getsizeof(packets)
    size_in_mbs = size_in_bytes / (1024 * 1024)

    print(f"Size of the list: {size_in_mbs} MB")
    print("----------------------------------------------")
    # print("deleted_packets len ", len(deleted_packets))


# Define a function for packet sniffing
def packet_sniffer():

    sniff(filter="tcp or udp", prn=process_packet, store=0,iface=interface)

if __name__ == "__main__":

    # Define the network interface to capture traffic from
    interface = "wlp0s20f3"

    # Print a start message
    print("Packet capturing started...")

    # Provide some instructions to the user.
    print("Sniffing will continue until this program is interrupted.")
    print("To stop sniffing, press Ctrl+C.")

    try:

        # thread_packet = threading.Thread(target=sniff, args=(iface=interface, prn=process_packet, store=0, filter="tcp or udp"))
        
        # Create and start the packet sniffing thread
        sniffer_thread = threading.Thread(target=packet_sniffer)
        sniffer_thread.start()

        threads_check = [threading.Thread(target=check_conditions) for _ in range(10)]
        threads_remove = [threading.Thread(target=remove_entries) for _ in range(10)]

        for thread in threads_check:
            thread.start()
        for thread in threads_remove:
            thread.start()

        # Wait for all threads to finish
        sniffer_thread.join()
        for thread in threads_check:
            thread.join()
        for thread in threads_remove:
            thread.join()
    except KeyboardInterrupt:
        print("\nInterrupt received! Stopping network sniffing...")

        print("The program has been closed.")