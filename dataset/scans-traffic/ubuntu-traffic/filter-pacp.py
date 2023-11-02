from scapy.all import PcapReader, PcapWriter, IP, TCP

# Replace 'your_input.pcap' with the path to your input PCAP file.
input_pcap_file = '/home/khattak01/Desktop/thesis/dataset/scans-traffic/tcp-syn/output_filtered.pcap'

# Replace 'output_filtered.pcap' with the desired name for the filtered PCAP output file.
output_pcap_file = 'ports_1000-6000_scan.pcap'

# Replace this with the IP address you want to filter (192.168.18.29 in your case).
ip_to_filter = '192.168.18.29'

# Replace this with the new IP address to replace the filtered IP address.
new_ip_address = '52.215.14.108'

# Open the input PCAP file for reading.
with PcapReader(input_pcap_file) as pcap_reader:
    # Create a new PCAP file to store filtered packets.
    output_pcap = PcapWriter(output_pcap_file)

    for packet in pcap_reader:
        # Check if the packet is a TCP packet and the source or destination IP matches the filter.
        if IP in packet and TCP in packet:
            if packet[IP].src == ip_to_filter:
                packet[IP].src = new_ip_address
            if packet[IP].dst == ip_to_filter:
                packet[IP].dst = new_ip_address
            output_pcap.write(packet)

print(f'Filtered packets with IP {ip_to_filter} replaced with {new_ip_address} and saved to {output_pcap_file}')
