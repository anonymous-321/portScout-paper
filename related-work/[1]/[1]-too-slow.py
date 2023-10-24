

from scapy.all import PcapReader
from scapy.all import *


from pyspark import SparkContext, SparkConf
from pyspark.sql import SparkSession

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

# Create a Spark session
conf = SparkConf().setAppName("FlowProcessing")
sc = SparkContext(conf=conf)
spark = SparkSession(sc)

packets = []
packets_rdd = sc.parallelize([])  # Initialize an empty RDD


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
    global packets_rdd  # Access the global RDD

    
    # tmp+=1

    ip_incoming_flows_count = [{}]
    ip_outgoing_flows_count = [{}]

    # print(len(ip_incoming_flows_count))
    # print(len(ip_outgoing_flows_count))

    # Process flow-level data
    packet = extract_packet_data(packet)
    # packets.append(packet)
    packet_rdd = sc.parallelize([packet])
    # Add the packet data to the global RDD
    packets_rdd = packets_rdd.union(packet_rdd)

    # Create an RDD from the 'packets' list

    # tmp+=1
    # print("tmp >>> ",tmp)
    
    # Check if packet's entry is already in the packets list and if the time difference is less than 30 seconds
    current_time = get_time()


    # Filter packets with matching source IP and a time difference less than 'time_threshold' seconds
    matching_packets = packets_rdd.filter(
        lambda pkt: pkt['src_ip'] == packet['src_ip'] and (current_time - pkt['timestamp']) < time_threshold
    )

    print("matching_packets >>> ", len(matching_packets.collect()))
    # Extract IP counts based on filtered packets
    for pkt in matching_packets.collect():
        if pkt['dst_ip'].startswith("192.168.137.") and pkt['src_ip'].startswith("192.168.137."):
            pass
        if pkt['src_ip'] == packet['src_ip']:
            ip_outgoing_flows_count.append(pkt)
        if pkt['dst_ip'] == packet['src_ip']:
            ip_incoming_flows_count.append(pkt)


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

    # Open the pcap file using PcapReader
    with PcapReader(pcap_file) as pcap_reader:
        # Loop through packets
            
        for packet in pcap_reader:

            process_packet(packet)
            # time.sleep(1)

            
            # packets_list.append(packet)
    # print(packets_list[2])
    