from scapy.all import PcapReader
from scapy.all import *

import datetime
import json

# from scans_traffic import files


def format_time(timestamp):
  # Convert the timestamp to a datetime object
  return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
 
  # Format the datetime object as a string
  # return dt.strftime("%Y-%m-%d %H:%M:%S")

def get_time():
  return datetime.datetime.now().timestamp()

current_file_name = ""

def update_alert_ips(ip):
    # Load existing data from the JSON file if it exists
    json_file_path = 'benign-alert_ips-20.json'
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

PORT_THRESHOLD = 20
TIME_THRESHOLD = 30

anomalous_ips = set()

packets = []

pkt_processed = 0


# Define the format_packet_data function
def extract_packet_data(packet):
    try:
        src_ip = dst_port = ""
        # packet.show()

        if TCP in packet or UDP in packet or SCTP in packet:

            if IP in packet:
                src_ip = packet[IP].src

                # packet coming towards the submit the detection system has installed
                if packet[IP].src.startswith("192.168.137"):
                    return False

            if TCP in packet:
                dst_port = packet[TCP].dport

            elif UDP in packet:
                dst_port = packet[UDP].dport
                
            elif SCTP in packet:
                dst_port = packet[SCTP].dport
        else:
            return False

        timestamp = get_time()

        return {
            "src_ip": src_ip,
            "dst_port": dst_port,
            "timestamp": timestamp,
        }  
   
    except Exception as e:
        print(f"Error extracting packet data: {e}")
        return False
   
def check_ports_packets(packet):
   
    # print(packet)

    packets = [p for p in packets if (get_time() - p["timestamp"] <= TIME_THRESHOLD)]

    for pkt in packets:

        if pkt['src_ip'] == packet["src_ip"]:
            if packet['dst_port'] not in pkt['dst_ports']:
                pkt['dst_ports'].add(packet['dst_port'])
   
            if len(pkt['dst_ports']) > PORT_THRESHOLD:
                dst_ip = pkt['src_ip']
                anomalous_ips.add(dst_ip)
                update_alert_ips(dst_ip)
                print("alert IP : ", dst_ip)
    else:
        ip_pkt = {
            'src_ip': packet['src_ip'],
            'dst_ports': [packet['dst_port']],
            'timestamp': packet['timestamp']
        }
        packets.append(ip_pkt)

def process_packet(packet):
    global pkt_processed
    global packets
    pkt_processed = pkt_processed + 1  

    if pkt_processed % 10000 == 0:
       print("pkt_processed >>> ", pkt_processed)
       print("len(packets) >>> ",len(packets))
       print("----------------------------------------------------------")

    packet = extract_packet_data(packet)
    if not packet:
        return
   
    if packet['src_ip'] in anomalous_ips:
        return

    packets = [p for p in packets if (get_time() - p["timestamp"] <= TIME_THRESHOLD)]

    for pkt in packets:
        if pkt['src_ip'] == packet["src_ip"]:
            if packet['dst_port'] not in pkt['dst_ports']:
                pkt['dst_ports'].append(packet['dst_port'])
   
                if len(pkt['dst_ports']) > PORT_THRESHOLD:
                    dst_ip = pkt['src_ip']
                    anomalous_ips.add(dst_ip)
                    update_alert_ips(dst_ip)
                    print("alert IP : ", dst_ip)
            break
    else:
        ip_pkt = {
            'src_ip': packet['src_ip'],
            'dst_ports': [packet['dst_port']],
            'timestamp': packet['timestamp']
        }
        packets.append(ip_pkt)

   

if __name__ == "__main__":

    # Record the start time
    start_time = time.time()

    print("Program start time >>> ", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    files = [
        # '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic1.pcap',
        # '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic2.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic.pcap',
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
        print(current_file_name, "DONE!")
        print("----------------------------------------------------------")


    # Record the end time
    end_time = time.time()
    # Calculate the time taken
    time_taken = end_time - start_time

    print(f"Time taken: {time_taken} seconds") 