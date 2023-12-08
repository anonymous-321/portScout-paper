from scapy.all import *
import math
from scapy.all import PcapReader
# from collections import defaultdict

import json
import datetime

packets = []

pkt_proccesd = 0

anomalous_ips = set()

current_file_name = ""

def update_alert_ips(ip):
    # Load existing data from the JSON file if it exists
    json_file_path = 'alert_ips-2.json'
    try:
        with open(json_file_path, 'r') as json_file:
            data = json.load(json_file)
    except FileNotFoundError:
        data = []

    # Add the new IP and current time to the data
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_entry = {'ip': ip, 'time': timestamp,"file":current_file_name}
    data.append(new_entry)

    # Save the updated data to the JSON file
    with open(json_file_path, 'w') as json_file:
        json.dump(data, json_file, indent=2)
        print(f"Alert IP {ip} saved with timestamp {timestamp} to {json_file_path}")


def extract_packet_data(packet):
    try:
        src_ip = dst_ip = src_port = dst_port = ""
        # packet.show()

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif SCTP in packet:
            src_port = packet[SCTP].sport
            dst_port = packet[SCTP].dport

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
        }
    except Exception as e:
        print(f"Error extracting packet data: {e}")


# def calculate_spd_per_ip(packets):
#     # Create dictionaries to keep track of source and destination flows for each IP
#     source_flows = defaultdict(int)
#     destination_flows = defaultdict(int)
#     spd_per_ip = {}

#     for packet in packets:
#         src_ip = packet["src_ip"]
#         dst_ip = packet["dst_ip"]

#         # Count source and destination flows for each IP
#         source_flows[src_ip] += 1
#         destination_flows[dst_ip] += 1

#     for ip in source_flows.keys():
#         spd = math.log(source_flows[ip] / destination_flows[ip])
#         spd_per_ip[ip] = spd

#     return spd_per_ip

# Define a function to calculate SPD (Source per Destination)
def calculate_spd_for_ip(packets, ip):
    source_flows = 0
    destination_flows = 0

    for packet in packets:
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]

        if src_ip == ip:
            source_flows += 1

        if dst_ip == ip:
            destination_flows += 1

    if destination_flows == 0:
        return float("inf")  # Handle the case where the denominator is zero

    spd = round(math.log(source_flows / destination_flows), 4)
    return spd



# Define a function to calculate PPI (Ports per IPs)
# def calculate_ppi(packets):
#     destination_ports = defaultdict(int)
#     destination_ip_addresses = defaultdict(int)
#     ppi_per_ip = {}

#     for packet in packets:
#         dst_ip = packet["dst_ip"]
#         dst_port = packet["dst_port"]

#         destination_ports[dst_ip] += 1
#         destination_ip_addresses[dst_ip] += 1

#     for ip in destination_ports.keys():
#         if destination_ip_addresses[ip] == 0:
#             ppi = float("inf")  # Handle the case where the denominator is zero
#         else:
#             ppi = math.log(destination_ports[ip] / destination_ip_addresses[ip])
#         ppi_per_ip[ip] = ppi

#     return ppi_per_ip


def calculate_ppi_for_ip(packets, ip):
    unique_dest_ips = set()
    unique_dest_ports = set()

    for packet in packets:
        if packet["src_ip"] == ip:
            unique_dest_ips.add(packet["dst_ip"])
            unique_dest_ports.add(packet["dst_port"])

    if unique_dest_ips == 0:
        ppi = float("inf")  # Handle the case where the denominator is zero
    else:
        ppi = round(math.log(len(unique_dest_ports) / len(unique_dest_ips)),4)

    return ppi

#experiment 2
#threashold for experiment 2, section 5 --> 5.2 --> column 2, last para
"""
horizontal port scan attack (PPI ≥ 4.52, SPD ≥ 2.98) and the green area de-
notes the hosts assumed to conduct a vertical port scan attack or
a host scan attack (PPI ≤ -4.52, SPD ≥ 2.98).
"""
def check_area(ppi,spd):
    if ppi >= 4.52 and spd <= 2.98:
        return "Red area"
    
    elif ppi <= -4.52 and spd >= 2.98:
        return "Green area"

    # benign 
    # None of the defined areas
    return "Undefined area"

    
def process_packet(packet):

    global pkt_proccesd
    # global current_file_name
    pkt_proccesd = pkt_proccesd + 1

    packet = extract_packet_data(packet)

    pkt_src_ip = packet['src_ip']
    if pkt_src_ip in anomalous_ips:
        return

    packets.append(packet)

    ppi = calculate_ppi_for_ip(packets, pkt_src_ip)
    sdp = calculate_spd_for_ip(packets,pkt_src_ip)

    # print(ppi)        
    # print(sdp)        
    # print(packet)
    # print(len(packets))
    #f rom paper, page 17 -> section results:5 -> 5.1 -> para 1
    # We defined that the red area is 4.0 ≤ PPI, 4.0 ≤ SPD, the green area is PPI ≤ −4.0, 4.0 ≤ SPD, and the yellow area is 4.0 ≤ PPI, SPD ≤ 2.0.
    res = check_area(ppi,sdp)
    if res=="Red area" or res=="Green area":
        print("Alert >>> ", pkt_src_ip)
        print(ppi)        
        print(sdp)        
        print(packet)

        anomalous_ips.add(pkt_src_ip)
        update_alert_ips(pkt_src_ip)
    
    # print(res)
    
    if pkt_proccesd % 10000 == 0:
        print("pkt_proccesed >>> ",pkt_proccesd)
        print('---------------------------------------------------')

if __name__=="__main__":

    print("Program start time >>> ",datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


    # print(check_area(0.31,3))
    # Replace 'pcap_file' with the path to your pcap file
    # pcap_file = '/home/khattak01/Desktop/thesis/dataset/scans-traffic/filtered-traffic/window-traffic/simple-scans-modified/filtered_nmap_top-ports-tcp-connect.pcap'

        
    files = [
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic2.pcap',
        ]

    # Record the start time
    start_time = time.time()

    for file in files:
        packets = []
        current_file_name = file
        # Open the pcap file using PcapReader
        current_pkt_time = 0
        prev_pkt_time = 0
        time_taken_by_process = 0
        with PcapReader(file) as pcap_reader:
            # Loop through packets
            for packet in pcap_reader:
                prev_pkt_time = current_pkt_time
                current_pkt_time = packet.time
                time_diff = current_pkt_time - prev_pkt_time - time_taken_by_process
                      
                # Ensure time_diff is non-negative
                time_diff = max(0, time_diff)
                # print(time_diff)
                # Check if prev_pkt_time is not zero before sleeping
                if prev_pkt_time != 0:
                    time.sleep(float(time_diff))
                        # Measure the time taken by process_packet
                start_time_p = time.time()
                process_packet(packet)
                end_time_p = time.time()

                # Calculate the time taken by process_packet
                time_taken_by_process = end_time_p - start_time_p

    # Record the end time
    end_time = time.time()
    # Calculate the time taken
    time_taken = end_time - start_time

    print(f"Time taken: {time_taken} seconds") 

