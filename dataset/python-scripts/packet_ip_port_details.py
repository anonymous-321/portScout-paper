from scapy.all import PcapReader
import threading
import time
from collections import defaultdict
import json

# Record the start time
start_time = time.time()

# Define the list of pcap files
pcap_files = [
    '/home/khattak01/Desktop/thesis/BenignTraffic/BenignTraffic.pcap',
    '/home/khattak01/Desktop/thesis/BenignTraffic/BenignTraffic1.pcap',
    '/home/khattak01/Desktop/thesis/BenignTraffic/BenignTraffic2.pcap',
    '/home/khattak01/Desktop/thesis/BenignTraffic/BenignTraffic3.pcap'
]

# Create dictionaries to count packets by protocol and IP addresses
packet_counts = {
    'ARP': 0,
    'ICMP': 0,
    'TCP': 0,
    'UDP': 0,
    'Other': 0,
}

src_ip_counts = defaultdict(int)
dst_ip_counts = defaultdict(int)

src_ports_counts = defaultdict(int)
dst_ports_counts = defaultdict(int)

# Function to process packets and update counts
def process_packets(pcap_file):
    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            # Count packets by protocol
            if packet.haslayer('ARP'):
                packet_counts['ARP'] += 1
            elif packet.haslayer('ICMP'):
                packet_counts['ICMP'] += 1
            elif packet.haslayer('TCP'):
                packet_counts['TCP'] += 1
                src_port = packet['TCP'].sport
                dst_port = packet['TCP'].dport
                src_ports_counts[src_port] += 1
                dst_ports_counts[dst_port] += 1
            elif packet.haslayer('UDP'):
                packet_counts['UDP'] += 1
                src_port = packet['UDP'].sport
                dst_port = packet['UDP'].dport
                src_ports_counts[src_port] += 1
                dst_ports_counts[dst_port] += 1
            else:
                packet_counts['Other'] += 1

            # Count source and destination IPs
            if 'IP' in packet:
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                src_ip_counts[src_ip] += 1
                dst_ip_counts[dst_ip] += 1

# Create a list of threads to process each pcap file
threads = []
for pcap_file in pcap_files:
    thread = threading.Thread(target=process_packets, args=(pcap_file,))
    threads.append(thread)

# Start all threads
for thread in threads:
    thread.start()

# Wait for all threads to finish
for thread in threads:
    thread.join()

# Save the data to separate JSON files
data = {
    'packet_counts': packet_counts,
    'src_ip_counts': src_ip_counts,
    'dst_ip_counts': dst_ip_counts,
    'src_ports_counts': src_ports_counts,
    'dst_ports_counts': dst_ports_counts
}

for key, value in data.items():
    with open(f'{key}.json', 'w') as json_file:
        json.dump(value, json_file)

# Calculate the total time taken
end_time = time.time()
total_time = end_time - start_time

# Print the total time taken
print(f"\nTotal time taken: {total_time} seconds")