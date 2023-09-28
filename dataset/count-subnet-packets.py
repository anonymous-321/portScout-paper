from scapy.all import PcapReader
import threading
import time

# Record the start time
start_time = time.time()

# Define the list of pcap files
pcap_files = [
    '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic.pcap',
    '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic1.pcap',
    '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic2.pcap',
    '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap'
]

# Create a lock to protect the shared variables
lock = threading.Lock()

# Initialize counts for packets with source and destination IPs in the "192.168.137" subnet
subnet_packet_count = 0

# Function to count packets with source and destination IPs in the subnet
def count_packets(pcap_file):
    global subnet_packet_count  # Declare as global

    local_subnet_packet_count = 0

    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            # Check if the packet has an IP layer
            if 'IP' in packet:
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst

                # Check if both source and destination IPs start with "192.168.137."
                if src_ip.startswith("192.168.137.") and dst_ip.startswith("192.168.137."):
                    local_subnet_packet_count += 1
            
            # Check if the count is a multiple of 100
            if local_subnet_packet_count % 1000 == 0:
                print(f"{pcap_file } Progress: {local_subnet_packet_count} packets stored")

    # Acquire the lock before updating the shared variables
    with lock:
        subnet_packet_count += local_subnet_packet_count

        # Print count for this pcap file
        print(f"{pcap_file}: {local_subnet_packet_count} packets")

# Create a list of threads to process each pcap file
threads = []
for pcap_file in pcap_files:
    thread = threading.Thread(target=count_packets, args=(pcap_file,))
    threads.append(thread)

# Start all threads
for thread in threads:
    thread.start()

# Wait for all threads to finish
for thread in threads:
    thread.join()

# Print the total count of packets with source and destination IPs in the "192.168.137" subnet
print("\nTotal packets with source and destination IPs in the '192.168.137' subnet:")
print(subnet_packet_count)

# Calculate the total time taken
end_time = time.time()
total_time = end_time - start_time

# Print the total time taken
print(f"\nTotal time taken: {total_time} seconds")
