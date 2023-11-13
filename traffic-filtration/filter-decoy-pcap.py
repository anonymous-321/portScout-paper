import os
from scapy.all import rdpcap, wrpcap

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
    # Replace these with the list of IP addresses you want to filter
    decoy_ips = ["192.168.18.21", "192.168.18.141", "192.168.18.29", "192.168.18.48", "192.168.18.53"]

    # Replace this with the path to the directory containing pcap files
    directory_path = '/home/khattak01/Desktop/thest-test/scans-traffic/ubuntu-traffic/evasion-technique-unfiltered-traffic/decoy'

    filter_and_save_pcap(directory_path, decoy_ips)
