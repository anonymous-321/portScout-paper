import os
import random
from scapy.all import rdpcap, wrpcap, IP

def filter_and_save_pcap(directory, decoy_ips):
    # Iterate through all files in the directory
    for filename in os.listdir(directory):
        input_filepath = os.path.join(directory, filename)
        
        # Check if the file is a pcap file
        if filename.endswith('.pcap'):
            print(f"Processing file: {filename}")

            # Read the pcap file
            packets = rdpcap(input_filepath)

            # Filter packets based on communication with the specified list of decoy IPs and '192.168.18.179'
            filtered_packets = [pkt for pkt in packets if 'IP' in pkt and pkt.haslayer('TCP')
                                and ((pkt['IP'].src in decoy_ips and pkt['IP'].dst == '192.168.18.179')
                                     or (pkt['IP'].src == '192.168.18.179' and pkt['IP'].dst in decoy_ips))]

            # Create a new filename for the output pcap file
            output_filename = f"filtered_{filename}"
            output_filepath = os.path.join(directory, output_filename)

            # Save the filtered packets to the new pcap file
            wrpcap(output_filepath, filtered_packets)
            print(f"Filtered packets saved to: {output_filename}")

if __name__ == "__main__":
    # Replace this with the range of IP addresses you want to filter
    distributed_ips = [f"192.168.18.{random.randint(50, 99)}" for _ in range(50)]  # Generate random source IPs
    distributed_ips.append("192.168.18.29")
    print(distributed_ips)

    # Replace this with the path to the directory containing pcap files
    directory_path = '/home/khattak01/Desktop/thest-test/scans-traffic/ubuntu-traffic/evasion-technique-unfiltered-traffic/distributed'

    filter_and_save_pcap(directory_path, distributed_ips)
