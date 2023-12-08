from scapy.all import PcapReader
from scapy.all import *
import datetime
import json

# from scans_traffic import files

THRESHOLD = 20
timeout = 30  # 30 seconds
tracker = []
pkt_processed = 0
anomalous_ips = set()

# Define the format_packet_data function
def extract_packet_data(packet):
    try:
        src_ip = dst_ip = tcp_flags = ""
        protocol = "Unknown"  # Default protocol

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            tcp_flags = packet[TCP].sprintf('%flags%')

        elif UDP in packet:
            protocol = "UDP"

        elif ICMP in packet:
            protocol = "ICMP"

        timestamp = datetime.datetime.now().timestamp()

        if not src_ip or not dst_ip:
            return False

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "tcp_flags": tcp_flags,
            "timestamp": timestamp,
        }
    except Exception as e:
        print(f"Error extracting packet data: {e}")
        return False

current_file_name = ""

def update_alert_ips(ip):
    # Load existing data from the JSON file if it exists
    json_file_path = 'alert_ips-20.json'
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

def process_packet(packet):
    global tracker

    global pkt_processed
    pkt_processed = pkt_processed + 1 

    if pkt_processed % 10000 == 0:
        print("pkt_processed >>> ", pkt_processed)
        print("----------------------------------------------------------") 

    packet_data = extract_packet_data(packet)
    if not packet_data:
        return

    pkt_src_ip = packet_data['src_ip']
    if pkt_src_ip in anomalous_ips:
        return


    if (packet_data['protocol'] == "TCP" and packet_data['tcp_flags'] == "S") or packet_data['protocol'] == "UDP" or packet_data['protocol'] == "ICMP":
        # print(packet_data)
        # print("----------------------------------------------------------")

        counter = ""
        if packet_data['protocol'] == "TCP" and packet_data['tcp_flags'] == "S":
            counter = "tcp_counter"
        elif packet_data['protocol'] == "UDP":
            counter = "udp_counter"
        elif packet_data['protocol'] == "ICMP":
            counter = "icmp_counter"


        # Calculate the current time
        current_time = datetime.datetime.now().timestamp()

        #Filter and update tracked connections based on timeout

        tracker = [conn for conn in tracker if (current_time - conn["timestamp"] <= timeout)]

        connection_found = False

        for conn in tracker:
            if conn['src_ip'] == packet_data['src_ip'] and conn['dst_ip'] == packet_data['dst_ip']:
                conn[counter] += 1
                connection_found = True

                if conn['tcp_counter'] > THRESHOLD or conn['udp_counter'] > THRESHOLD or conn['icmp_counter'] > THRESHOLD:
                    pass
                    # Counter has reached or exceeded the threshold
                    # print("Alert >>> ", conn)
                    anomalous_ips.add(pkt_src_ip)
                    update_alert_ips(pkt_src_ip)
                    # print("Alert >>> Scanning", conn)
                    print("Set a flow entry to drop packets from the attacker", packet_data['src_ip'], "  >>> ", packet_data['dst_ip'])

        if not connection_found:
            # New connection
            new_connection = {
                'src_ip': packet_data['src_ip'],
                'dst_ip': packet_data['dst_ip'],
                'protocol': packet_data['protocol'],
                'timestamp': packet_data['timestamp'],
                'tcp_counter': 0,
                'udp_counter': 0,
                'icmp_counter': 0,
            }
            new_connection[counter] = 1  # Initialize the correct counter

            tracker.append(new_connection)

if __name__ == "__main__":

    # Record the start time
    start_time = time.time()
    print("Program start time >>> ", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Replace 'pcap_file' with the path to your pcap file
    # files = ['/home/khattak01/Desktop/port-scanning-detection-paper-main/dataset/scans-traffic/filtered-traffic/ubuntu-traffic/simple-scans-modified-traffic/filtered_nmap_top-ports_tcp-syn-.pcap']
    
    # file = "/home/khattak01/Desktop/port-scanning-detection-paper-main/dataset/BenignTraffic/1100000-pks/BenignTraffic-packets-250000.pcap"
    files = [
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic1.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic2.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap'
    ]

    for file in files:
        tracker = []
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
            print(current_file_name,"Done!")
    # Record the end time

    # # print("len(tracker) >>>", len(tracker))
    # # print("tracker >>>", tracker)
    # # Record the end time
    end_time = time.time()
    # Calculate the time taken
    time_taken = end_time - start_time

    print(f"Time taken: {time_taken} seconds") 
