from scapy.all import PcapReader
from scapy.all import *

import datetime
import json

current_file_name = ""

def format_time(timestamp):
  # Convert the timestamp to a datetime object
  return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
  
  # Format the datetime object as a string
  # return dt.strftime("%Y-%m-%d %H:%M:%S")

def get_time():
  return datetime.datetime.now().timestamp()

def update_alert_ips(ip):
    # Load existing data from the JSON file if it exists
    json_file_path = 'alert_ips-40-files-3-4.json'
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


# Define parameters
time_threshold = 30 #30 seconds
threshold = 40

anomalous_ips = set()

packets = []

pkt_proccesd = 0

# Define the format_packet_data function
def extract_packet_data(packet):
    try:
        src_ip = dst_ip = src_port = dst_port = ""
        protocol = "Unknown"
        # packet.show()

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif SCTP in packet:
            protocol = "SCTP"
            src_port = packet[SCTP].sport
            dst_port = packet[SCTP].dport

        elif ICMP in packet:
            protocol = "ICMP"
            # ICMP does not have source and destination ports, so setting them to None
            src_port = None
            dst_port = None
        else:
            # Handle other protocols if needed
            protocol = "Unknown"
            src_port = None
            dst_port = None   

        timestamp = get_time()

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol":protocol,
            "timestamp": timestamp,
        }   
    
    except Exception as e:
        print(f"Error extracting packet data: {e}")

def process_packet(packet):
    
    global pkt_proccesd
    # global current_file_name
    pkt_proccesd = pkt_proccesd + 1
    global packets

    ip_incoming_flows_count = [{}]
    ip_outgoing_flows_count = [{}]

    # print(len(ip_incoming_flows_count))
    # print(len(ip_outgoing_flows_count))


    # Process flow-level data
    packet = extract_packet_data(packet)

    pkt_src_ip = packet['src_ip']
    if pkt_src_ip in anomalous_ips:
        return
    
    packets.append(packet)

    
    # Check if packet's entry is already in the packets list and if the time difference is less than 30 seconds
    current_time = get_time()
    # print(packet['timestamp'])
    # print(current_time)
    # print((current_time - packet['timestamp']))
    # print(time_threshold)
    packets = [pkt for pkt in packets if (current_time - pkt['timestamp']) < time_threshold]
    time_threshold_packets = [pkt for pkt in packets if (pkt['src_ip'] == pkt_src_ip or pkt['dst_ip'] == pkt_src_ip)]

    # print(len(matching_packets))
    # return

    if time_threshold_packets:
        for pkt in time_threshold_packets:
            # print(pkt)
            # Check if both source and destination IPs start with "192.168.137."
            # if pkt['src_ip'].startswith("192.168.137.") and pkt['dst_ip'].startswith("192.168.137."):
            if pkt['protocol'] not in ["TCP","UDP","SCTP","ICMP"]:
                pass
            
            if pkt['src_ip'] == pkt_src_ip:
                ip_outgoing_flows_count.append(packet)
            
            else:
                # pkt['dst_ip'] == packet['src_ip']:
                ip_incoming_flows_count.append(packet)

    ratio = 0
    if len(ip_incoming_flows_count) >= len(ip_outgoing_flows_count):
        ratio = len(ip_incoming_flows_count) / len(ip_outgoing_flows_count) if len(ip_outgoing_flows_count) > 0 else 1
    
    else:
        ratio = len(ip_outgoing_flows_count) / len(ip_incoming_flows_count) if len(ip_incoming_flows_count) > 0 else 1


    if ratio > threshold:

        anomly_ip = packet['src_ip']
        anomalous_ips.add(anomly_ip)
        update_alert_ips(anomly_ip)
        print("alert IP : ",anomly_ip)
        # packets = []


    if pkt_proccesd % 10000 == 0:
        print("pkt_proccesed >>> ",pkt_proccesd)
    
    # print("ip_outgoing_flows_count >>> ",len(ip_outgoing_flows_count))
    # print("ip_incoming_flows_count >>> ",len(ip_incoming_flows_count))
    # print("----------------------------------------------------------")

    # Get CPU and memory usage
    # cpu_usage = psutil.cpu_percent(interval=1)
    # memory_usage = psutil.virtual_memory().percent

    # # Print the usage
    # print(f"CPU Usage: {cpu_usage}% | Memory Usage: {memory_usage}%")
    # print(tmp)
    # print(packet['src_ip'])

from scans_traffic import files
if __name__ == "__main__":

    print("Program start time >>> ",datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    # Replace 'pcap_file' with the path to your pcap file
    # pcap_file = '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap'
    # pcap_file = '/home/khattak01/Desktop/thesis/dataset/scans-traffic/filtered-traffic/window-traffic/simple-scans-modified/filtered_nmap_top-ports-tcp-connect.pcap'

    # files = ['/home/khattak01/Desktop/thesis/dataset/BenignTraffic/1500000-packets/BenignTraffic-packets-200000.pcap']
            #  '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic1.pcap',
            #  '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic2.pcap',
            #  '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap']

    # files =  ['/home/khattak01/Desktop/thesis/tests/packets-10000-1.pcap',
    #           '/home/khattak01/Desktop/thesis/tests/packets-10000-2.pcap',
    #           '/home/khattak01/Desktop/thesis/tests/packets-10000-3.pcap',
    #           '/home/khattak01/Desktop/thesis/tests/packets-10000-4.pcap']
    
    # files = ["dataset/scans-traffic/filtered-traffic/ubuntu-traffic/evasion-technique-modified-traffic/slow-scan/filtered_slow-scan-1000ports-ramdom-pkts(20-30)-radom-delay1-10s.pcap"]
    
    files = [
        #'/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic.pcap',
        #'/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic1.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic2.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap'
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
