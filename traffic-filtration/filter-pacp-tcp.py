import os
from scapy.all import rdpcap, wrpcap

def filter_and_save_pcap(directory, ip_to_filter_1, ip_to_filter_2):
    # Iterate through all files in the directory
    for filename in os.listdir(directory):
        input_filepath = os.path.join(directory, filename)
        
        # Check if the file is a pcap file
        if filename.endswith('.pcap'):
            print(f"Processing file: {filename}")

            # Read the pcap file
            packets = rdpcap(input_filepath)

            # Filter packets based on exclusive communication between the specified IP addresses
            filtered_packets = [pkt for pkt in packets if 'IP' in pkt and pkt.haslayer('TCP')
                                and ((pkt['IP'].src == ip_to_filter_1 and pkt['IP'].dst == ip_to_filter_2)
                                     or (pkt['IP'].src == ip_to_filter_2 and pkt['IP'].dst == ip_to_filter_1))]

            # Create a new filename for the output pcap file
            output_filename = f"filtered_{filename}"
            output_filepath = os.path.join(directory, output_filename)

            # Save the filtered packets to the new pcap file
            wrpcap(output_filepath, filtered_packets)
            print(f"Filtered packets saved to: {output_filename}")

if __name__ == "__main__":
    # Replace these with the IP addresses you want to filter
    ip_to_filter_1 = '192.168.18.29'
    ip_to_filter_2 = '192.168.18.179'

    # Replace this with the path to the directory containing pcap files
    directory_path = '/home/khattak01/Desktop/thest-test/scans-traffic/ubuntu-traffic/evasion-technique-unfiltered-traffic/test'

    filter_and_save_pcap(directory_path, ip_to_filter_1, ip_to_filter_2)
