import os
import json
from scapy.all import *

from scans_traffic import files

def extract_ips_from_packet(packet):
    ip_addresses = set()

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Ignore IPs starting with '192.168.137.'
        if not src_ip.startswith('192.168.137.'):
            ip_addresses.add(src_ip)
        if not dst_ip.startswith('192.168.137.'):
            ip_addresses.add(dst_ip)

    return list(ip_addresses)

def process_pcap_files(file_paths):
    result = {}

    for file_path in file_paths:
        ip_addresses = set()

        try:
            # Load the pcap file
            packets = rdpcap(file_path)

            # Extract unique IP addresses
            for packet in packets:
                src_ip = packet[IP].src
                # dst_ip = packet[IP].dst
                if not src_ip.startswith('192.168.137.'):
                    ip_addresses.add(src_ip)
                    # ip_addresses.extend(extract_ips_from_packet(packet))

        except Exception as e:
            print(f"Error processing {file_path}: {e}")

        # Convert set to list before saving to JSON
        result[file_path] = list(ip_addresses)
        print(result)
        print("FILE DONE!", file_path)

    return result

def save_to_json(data, output_file):
    with open(output_file, 'w') as json_file:
        json.dump(data, json_file, indent=4)

if __name__ == "__main__":
    json_output_file = "output.json"
    result_data = process_pcap_files(files)
    save_to_json(result_data, json_output_file)
    print(f"Results saved to {json_output_file}")
