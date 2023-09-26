from scapy.all import PcapReader
import threading
import time

# Record the start time
start_time = time.time()

# Define the list of pcap files
pcap_files = [
    '/home/khattak01/Desktop/thesis/BenignTraffic/BenignTraffic.pcap',
    '/home/khattak01/Desktop/thesis/BenignTraffic/BenignTraffic1.pcap',
    '/home/khattak01/Desktop/thesis/BenignTraffic/BenignTraffic2.pcap',
    '/home/khattak01/Desktop/thesis/BenignTraffic/BenignTraffic3.pcap'
]

# Create dictionaries to count packets by protocol
packet_counts = {
    'ARP': 0,
    'ICMP': 0,
    'TCP': 0,
    'UDP': 0,
    'Other': 0,
}

# Create a lock to protect the shared packet_counts dictionary
lock = threading.Lock()

# Function to count packets by protocol for a given pcap file
def count_packets_by_protocol(pcap_file):
    local_counts = {
        'ARP': 0,
        'ICMP': 0,
        'TCP': 0,
        'UDP': 0,
        'Other': 0,
    }
    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if packet.haslayer('ARP'):
                local_counts['ARP'] += 1
            elif packet.haslayer('ICMP'):
                local_counts['ICMP'] += 1
            elif packet.haslayer('TCP'):
                local_counts['TCP'] += 1
            elif packet.haslayer('UDP'):
                local_counts['UDP'] += 1
            else:
                local_counts['Other'] += 1

            # Check if the count is a multiple of 100,000
            if sum(local_counts.values()) % 100000 == 0:
                print(f"Progress: {sum(local_counts.values())} packets processed")

    # Acquire the lock before updating the shared dictionary
    with lock:
        for protocol in local_counts:
            packet_counts[protocol] += local_counts[protocol]
        print(local_counts)

# Create a list of threads to process each pcap file
threads = []
for pcap_file in pcap_files:
    thread = threading.Thread(target=count_packets_by_protocol, args=(pcap_file,))
    threads.append(thread)

# Start all threads
for thread in threads:
    thread.start()

# Wait for all threads to finish
for thread in threads:
    thread.join()

# Print the packet counts by protocol for all files
for protocol, count in packet_counts.items():
    print(f"{protocol}: {count} packets")

# Calculate the total time taken
end_time = time.time()
total_time = end_time - start_time

# Print the total time taken
print(f"Total time taken: {total_time} seconds")
