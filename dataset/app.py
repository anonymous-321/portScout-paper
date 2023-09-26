from scapy.all import PcapReader, IP, send

# Replace 'pcap_file' with the path to your pcap file
pcap_file = '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap'

# Define the destination IP address
destination_ip = '192.168.18.179'

count = 0
# Open the pcap file using PcapReader
with PcapReader(pcap_file) as pcap_reader:
    # Loop through packets
    for packet in pcap_reader:
        
        count +=1
        print(f"Count: {count}")
