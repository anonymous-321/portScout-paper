# from scapy.all import *
import threading


from scapy.layers.inet import IP, TCP, UDP
from scapy.all import sniff

# from packet import Packet
from util import get_time


PORT_THRESHOLD = 15
TIME_THRESHOLD = 15
DELETE_TIME_THRESHOLD = 60

# Create a list to store packet data
packets = []
scanner_packets = {}
# scan_count = 0

# Define a lock to synchronize access to the 'packets' list
packets_lock = threading.Lock()

# Function to insert a packet into the list
def insert_packet(packet):
    with packets_lock:
        packets.append(packet)

# Function to delete a packet from the 'packets' list
def delete_packet(packet_index):
    with packets_lock:
        del packets[packet_index]

def remove_entries():
    print("------------remove_entries------------")

    # return
    if not len(packets):
        return
        
    current_time = get_time()
    # with packets_lock:
    for i in range (len(packets)):
        diff = int(current_time - float(packets[i].split('_')[-1]))
        # print(diff)
        if diff > DELETE_TIME_THRESHOLD:
                delete_packet(i)
                # del packets[i]
                # print("Data deleted", packets[i])
    # Reschedule the function to be called after 1 seconds
    # threading.Timer(1, remove_entries).start()

def save_scanner_data(packet):
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

def check_ports_packets(packets):
    dst_ports = []

    for packet in packets:
        packet_port = packet.split('_')[3]
        if not len(dst_ports):
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
                    dst_ports[i]['packets'] = t
                    tmp = False
                    break
            # else:
                # t = dst_ports[i]['packets']
                # t.append(packet)
            if tmp:
                dst_ports.append({'port': packet_port, 'packets': [packet]})
                # break

    # print(dst_ports)               
    # print(len(dst_ports))               
    return dst_ports


def check_conditions():
    print("------------check_conditions------------")
    if not len(packets):
        return
    
    ports = check_ports_packets(packets)
    # print(" -------------------> ",len(ports))
    if len(ports) > PORT_THRESHOLD:
        # tmp = True
        port_data = set()
        for port in ports:
            # if not tmp:
            #     break
            # tmp_list = []
            tmp_flg = True
            for p_p in port['packets']:
                timestamp = float(p_p.split('_')[-1])
                # current_time = get_time()
                time_diff = int(get_time() - timestamp)
                # print("time - diff",time_diff)
                if time_diff < TIME_THRESHOLD:
                    # tmp_list.append()
                    if tmp_flg:
                        port_data.add(port['port'])
                        tmp_flg = False
                    with packets_lock:
                        #push this data somemwhere, as this list will have the last one min packet if someone try to scan
                        save_scanner_data(p_p) 
                        packets.remove(p_p)
            if len(port_data)>PORT_THRESHOLD:
                # print(len(port))
                # with packets_lock:
                    # global scan_count 
                    # scan_count = scan_count + 1
                print("Scanning Alert")
                # print(scan_count)
    # threading.Timer(1, check_conditions).start()



def process_packet(packet):
    """
    Process the captured packet and extract header information for TCP and UDP packets with the IP layer.
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
    # # print((packets))

    # size_in_bytes = sys.getsizeof(packets)
    # size_in_mbs = size_in_bytes / (1024 * 1024)

    # print(f"Size of the list: {size_in_mbs} MB")
    # print("----------------------------------------------\n")
    print("packets len ", len(packets))
    print(len(scanner_packets))

    # Get the number of threads running in the current program
    num_threads = threading.active_count()

    print("Number of threads running:", num_threads)
    check_conditions()
    remove_entries()

# Define a function for packet sniffing
def packet_sniffer():
    # Define the network interface to capture traffic from
    interface = "wlp0s20f3"
    # When store is set to 0, it means that the captured packets will not be stored in memory. Instead, 
    # they will be processed by the callback function (prn) immediately as they are captured. This is 
    # useful when dealing with a large number of packets or when memory usage needs to be minimized.
    sniff(filter="tcp or udp", prn=process_packet, store=0,iface=interface)

def run_threads():
    threads_check = [threading.Thread(target=check_conditions) for _ in range(15)]
    threads_remove = [threading.Thread(target=remove_entries) for _ in range(5)]
    # Start the Timer objects to execute the check_conditions and remove_entries functions
    for _ in range(5):
        threading.Timer(2, remove_entries).start()

    for _ in range(15):
        threading.Timer(2, check_conditions).start()

    
if __name__ == "__main__":


    # Print a start message
    print("Packet capturing started...")

    # Provide some instructions to the user.
    print("Sniffing will continue until this program is interrupted.")
    print("To stop sniffing, press Ctrl+C.")

    try:
        # Create and start the packet sniffing thread
        sniffer_thread = threading.Thread(target=packet_sniffer)
        sniffer_thread.start()
        

        # threads_check = [threading.Thread(target=check_conditions) for _ in range(15)]
        # threads_remove = [threading.Thread(target=remove_entries) for _ in range(5)]
        # for thread in threads_check:
        #     thread.start()
        # for thread in threads_remove:
        #     thread.start()

        # threads_check = [threading.Thread(target=check_conditions) for _ in range(15)]
        # threads_remove = [threading.Thread(target=remove_entries) for _ in range(5)]

        # for thread in threads_check:
        #     thread.start()
        # for thread in threads_remove:
        #     thread.start()

    except KeyboardInterrupt:
        print("\nInterrupt received! Stopping network sniffing...")

        print("The program has been closed.")