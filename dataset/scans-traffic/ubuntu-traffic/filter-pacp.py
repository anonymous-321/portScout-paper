from scapy.all import PcapReader, PcapWriter, IP, TCP

# Replace 'your_input.pcap' with the path to your input PCAP file.
input_pcap_file = '/home/khattak01/Desktop/thesis/dataset/scans-traffic/ubuntu-traffic/filtered-traffic/top-ports-tcp-syn-scan.pcap'

# Replace 'output_filtered.pcap' with the desired name for the filtered PCAP output file.
output_pcap_file = 'top-ports-tcp-syn-scan.pcap'

# Replace this with the IP addresses you want to filter.
ip_to_filter_1 = '192.168.18.29'
ip_to_filter_2 = '192.168.18.179'

# Replace this with the new IP address to replace the filtered IP addresses.
new_ip_address = '52.215.14.108'

# Open the input PCAP file for reading.
with PcapReader(input_pcap_file) as pcap_reader:
    # Create a new PCAP file to store filtered packets.
    output_pcap = PcapWriter(output_pcap_file)

    for packet in pcap_reader:
        # Check if the packet is a TCP packet and the source or destination IP matches the filters.
        if IP in packet and TCP in packet:
            if (packet[IP].src == ip_to_filter_1 and packet[IP].dst == ip_to_filter_2) or (packet[IP].src == ip_to_filter_2 and packet[IP].dst == ip_to_filter_1):
                packet[IP].src = new_ip_address
                packet[IP].dst = new_ip_address
            output_pcap.write(packet)

print(f'Filtered packets with IP {ip_to_filter_1} and {ip_to_filter_2} replaced with {new_ip_address} and saved to {output_pcap_file}')
