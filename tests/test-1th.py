from pyspark.sql import SparkSession
from scapy.all import PcapReader
from collections import defaultdict

# Create a SparkSession
spark = SparkSession.builder.appName("PacketProcessing").getOrCreate()

# Define parameters
# time_interval = timedelta(seconds=30)
# threshold = 0.8

# Create dictionaries to store flow counts and anomalous IPs
flow_counts = defaultdict(int)
incoming_flows = []
outgoing_flows = []
anomalous_ips = set()

# Replace 'pcap_file' with the path to your pcap file
pcap_file = '/home/khattak01/Desktop/thesis/tests/packets-500.pcap'

# Read the pcap file using PySpark
packets_rdd = spark.sparkContext.binaryFiles(pcap_file).flatMap(lambda x: PcapReader(x[1]))

# Define the format_packet_data function
def extract_packet_data(packet):
    try:
        src_ip = dst_ip = src_port = dst_port = ""
        protocol = "Unknown"

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

        timestamp = str(get_time())

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "timestamp": timestamp,
        }
    except Exception as e:
        print(f"Error extracting packet data: {e}")

def process_packet(packet):
    global flow_counts, incoming_flows, outgoing_flows, anomalous_ips

    # Process flow-level data
    packet_data = extract_packet_data(packet)

    # Your flow-level processing logic here
    # Update dictionaries and perform checks

# Apply the process_packet function to each packet in parallel
packets_rdd.foreach(process_packet)

# Stop the SparkSession
spark.stop()



