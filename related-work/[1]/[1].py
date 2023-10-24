

from scapy.all import PcapReader
from scapy.all import *


import datetime

def format_time(timestamp):
  # Convert the timestamp to a datetime object
  return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
  
  # Format the datetime object as a string
  # return dt.strftime("%Y-%m-%d %H:%M:%S")

def get_time():
  return datetime.datetime.now().timestamp()


# Define parameters
time_threshold = 30 #30 seconds
threshold = 100

anomalous_ips = set()

packets = []

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
tmp = 0
def process_packet(packet):
    global tmp
    
    # tmp+=1

    ip_incoming_flows_count = [{}]
    ip_outgoing_flows_count = [{}]

    # print(len(ip_incoming_flows_count))
    # print(len(ip_outgoing_flows_count))

    # Process flow-level data
    packet = extract_packet_data(packet)
    packets.append(packet)


    # tmp+=1
    # print("tmp >>> ",tmp)
    
    # Check if packet's entry is already in the packets list and if the time difference is less than 30 seconds
    current_time = get_time()
    # print(packet['timestamp'])
    # print(current_time)
    # print((current_time - packet['timestamp']))
    print(time_threshold)
    time_threshold_packets = [pkt for pkt in packets if pkt['src_ip'] == packet['src_ip'] and 
                         (current_time - pkt['timestamp']) < time_threshold]
    # print(len(matching_packets))
    # return

    if time_threshold_packets:
        for pkt in time_threshold_packets:
            # Check if both source and destination IPs start with "192.168.137."
            if pkt['src_ip'].startswith("192.168.137.") and pkt['dst_ip'].startswith("192.168.137."):
                pass
            
            if pkt['src_ip'] == packet['src_ip']:
                ip_outgoing_flows_count.append(packet)
            
            if pkt['dst_ip'] == packet['src_ip']:
                ip_incoming_flows_count.append(packet)

        # elif packet['dst_ip'].startswith("192.168.137."):
        #         # packet.flow = "incoming"
        #     incoming_flows.append(packet)

        # elif packet['src_ip'].startswith("192.168.137."):
        #     # packet.flow = "outgoing"
        #     outgoing_flows.append(packet)

    ratio = 0
    if len(ip_incoming_flows_count) >= len(ip_outgoing_flows_count):
        ratio = len(ip_incoming_flows_count) / len(ip_outgoing_flows_count) if len(ip_outgoing_flows_count) > 0 else 1
    
    else:
        ratio = len(ip_outgoing_flows_count) / len(ip_incoming_flows_count) if len(ip_incoming_flows_count) > 0 else 1


    if ratio > threshold:
        print("alert IP : ",packet['src_ip'])


    # print(tmp)
    print(packet)
    print("ip_outgoing_flows_count >>> ",len(ip_outgoing_flows_count))
    print("ip_incoming_flows_count >>> ",len(ip_incoming_flows_count))
    print("----------------------------------------------------------")
if __name__ == "__main__":


    # Replace 'pcap_file' with the path to your pcap file
    pcap_file = '/home/khattak01/Desktop/thesis/tests/packets-500.pcap'

    packets_list = []

    # Open the pcap file using PcapReader
    with PcapReader(pcap_file) as pcap_reader:
        # Loop through packets
        for packet in pcap_reader:
            process_packet(packet)
            # time.sleep(1)

            
            # packets_list.append(packet)
    # print(packets_list[2])
    