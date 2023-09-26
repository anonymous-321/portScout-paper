from scapy.all import PcapReader, send

# Replace 'pcap_file' with the path to your pcap file
pcap_file = '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap'

# Define the destination IP address
destination_ip = '192.168.18.179'

# Open the pcap file using PcapReader
with PcapReader(pcap_file) as pcap_reader:
    # Loop through packets
    for packet in pcap_reader:
        # Check if the packet has an IP layer
        if packet.haslayer('IP'):
            # Change the destination IP address
            packet['IP'].dst = destination_ip

            print(packet)

            # Send the packet to the new destination
            send(packet, verbose=False)
