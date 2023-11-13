import os
import random
from scapy.all import rdpcap, wrpcap, IP

def replace_and_save_pcap(directory, output_directory):
    # Iterate through all files in the directory
    for filename in os.listdir(directory):
        input_filepath = os.path.join(directory, filename)

        # Check if the file is a pcap file
        if filename.endswith('.pcap'):
            print(f"Processing file: {filename}")

            # Read the pcap file
            packets = rdpcap(input_filepath)

            # Generate random IPs for replacement
            random_ip_1 = f"192.168.137.{random.randint(10, 250)}"
            random_ip_2 = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

            # Replace IP '192.168.18.179' with random_ip_1 and '192.168.18.29' with random_ip_2
            for pkt in packets:
                if IP in pkt:
                    pkt[IP].src = pkt[IP].src.replace('192.168.18.29', random_ip_2)
                    pkt[IP].dst = pkt[IP].dst.replace('192.168.18.29', random_ip_2)
                    pkt[IP].src = pkt[IP].src.replace('192.168.18.179', random_ip_1)
                    pkt[IP].dst = pkt[IP].dst.replace('192.168.18.179', random_ip_1)

            # Create a new filename for the output pcap file
            output_filename = f"filtered_{filename}"
            output_filepath = os.path.join(output_directory, output_filename)

            # Save the modified packets to the new pcap file
            wrpcap(output_filepath, packets)
            print(f"Modified packets saved to: {output_filename}")

if __name__ == "__main__":
    # Replace this with the path to the directory containing pcap files
    input_directory_path = '/home/khattak01/Desktop/thest-test/scans-traffic/window-traffic/evasion-technique-unfiltered-traffic/distributed'

    # Replace this with the path to the directory where you want to save modified pcap files
    output_directory_path = '/home/khattak01/Desktop/thest-test/scans-traffic/window-traffic/evasion-technique-filtered-traffic/distributed'

    replace_and_save_pcap(input_directory_path, output_directory_path)
