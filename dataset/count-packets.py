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

# Initialize a dictionary to store packet counts for each file
packet_counts = {}

# Create a lock to protect the shared packet_counts dictionary
lock = threading.Lock()

# Function to count packets for a given pcap file
def count_packets(pcap_file):
    count = 0
    with PcapReader(pcap_file) as pcap_reader:
        # Loop through packets in the file
        for _ in pcap_reader:
            count += 1

            # Check if the count is a multiple of 100,000
            if count % 100000 == 0:
                print(f"{pcap_file} PACKETS COUNT: {count}")

    # Acquire the lock before updating the shared dictionary
    with lock:
        packet_counts[pcap_file] = count


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

# Print the packet counts for each file
for pcap_file, count in packet_counts.items():
    print(f"{pcap_file}: {count} packets")

# Calculate the total time taken
end_time = time.time()
total_time = end_time - start_time

# Print the total time taken
print(f"Total time taken: {total_time} seconds")


















# # Define the list of pcap files
# pcap_files = [
#     '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic.pcap',
#     '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic1.pcap',
#     '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic2.pcap',
#     '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap'
# ]

# # Define the destination IP address
# destination_ip = '192.168.18.179'

# # Initialize a dictionary to store packet counts for each file
# packet_counts = {}

# # Loop through pcap files
# for pcap_file in pcap_files:
#     count = 0
#     with PcapReader(pcap_file) as pcap_reader:

#         # Loop through packets in each file
#         for packet in pcap_reader:
#             count += 1

#             # Check if the count is a multiple of 100,000
#             if count % 100000 == 0:
#                 print(f"{pcap_file} PACKETS COUNT : {count}")

#     # Store the packet count in the dictionary
#     packet_counts[pcap_file] = count

# # Print the packet counts for each file
# for pcap_file, count in packet_counts.items():
#     print(f"{pcap_file}: {count} packets")
