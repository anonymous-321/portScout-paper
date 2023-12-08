from scapy.all import PcapReader
from scapy.all import *
import json
import datetime
# from scans_traffic import files 

THRESHOLD = 20
anomalous_ips = set()

pkt_processed = 0

tracker = []

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

# Define the format_packet_data function
def extract_packet_data(packet):
    try:
        src_ip = dst_ip = ""
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if TCP not in packet:
            return False
        
        # Access the TCP flags and create a string representation
        # flags = []

        # if packet[TCP].flags & TCP.flags.S:
        #     flags.append('A')
        # if packet[TCP].flags & TCP.flags.A:
        #     flags.append('A')

        tcp_flags = packet[TCP].sprintf('%flags%')
        
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "tcp_flags": tcp_flags,
        }
       
    except Exception as e:
        print(f"Error extracting packet data: {e}")
        return False

def process_packet(packet):
    global tracker

    global pkt_processed
    pkt_processed = pkt_processed + 1 

    if pkt_processed % 10000 == 0:
        print("pkt_processed >>> ", pkt_processed)
        print("----------------------------------------------------------") 
    
    packet = extract_packet_data(packet)

    if not packet:
        return
    pkt_src_ip = packet['src_ip']
    if pkt_src_ip in anomalous_ips:
        return
    
    # print(packet)
    # print("----------------------------------------------------------")
    
    if not packet:
        return
    
    if packet['tcp_flags']=="SA" or packet['tcp_flags']=="S":
        # print(packet)
        # print("----------------------------------------------------------")
        if packet['tcp_flags'] == 'S':  # Packet is SYN
            connection_found = False

            for conn in tracker:
                if conn['src_ip'] == packet['src_ip'] and conn['dst_ip'] == packet['dst_ip']:
                    conn['counter'] += 1
                    connection_found = True

                    if conn['counter'] < THRESHOLD:
                        # Counter is below the threshold, do nothing
                        pass
                    else:
                        # Counter has reached or exceeded the threshold
                        anomalous_ips.add(pkt_src_ip)
                        update_alert_ips(pkt_src_ip)
                        print("Set a flow entry to drop packets from the attacker", packet['src_ip'], "  >>> ",packet['dst_ip'])

            if not connection_found:
                # New connection
                new_connection = {
                    'src_ip': packet['src_ip'],
                    'dst_ip': packet['dst_ip'],
                    'counter': 1,
                }
                tracker.append(new_connection)

        else:  # Packet is not SYN
            # connection_found = False

            for conn in tracker:
                if conn['src_ip'] == packet['src_ip'] and conn['dst_ip'] == packet['dst_ip']:
                    conn['counter'] -= 1
            #         connection_found = True

            # if not connection_found:
            #     # New connection (this should not happen for SYN-ACK packets)
            #     pass



if __name__ == "__main__":
    # Replace 'pcap_file' with the path to your pcap file
    # pcap_file = '/home/khattak01/Desktop/port-scanning-detection-paper-main/dataset/BenignTraffic/1100000-pks/BenignTraffic-packets-250000.pcap'

    # files = []
    files = [
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic1.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic2.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap'
    ]

    # Record the start time
    start_time = time.time()
    print("Program start time >>> ", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Record the start time
    start_time = time.time()

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
        print(current_file_name, "DONE!")
        print("----------------------------------------------------------")


    # Record the end time
    end_time = time.time()
    # Calculate the time taken
    time_taken = end_time - start_time

    print(f"Time taken: {time_taken} seconds") 
