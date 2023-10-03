from scapy.all import PcapReader
from scapy.all import PcapReader, IP, TCP
from scapy.all import *

# The proposed solution is for DDoS detection and port scan detection.
# In port scan detection, # The proposed solution focuses on detecting FIN scans, NULL scans, and ACK scans.

error_packets = 0

# Initialize a dictionary to store the scan counts
scan_counts = {
    "ACK": 0,
    "SYNFIN": 0,
    "NULL": 0,
}

def detect_scan(pkt):
    global scan_counts  # Use the global scan_counts dictionary
    if Ether in pkt:
        pkt = pkt[IP]  # Extract the IP layer from the Ethernet frame

        if TCP in pkt and (pkt[TCP].flags=="A" and pkt[TCP].ack == 0):# check for null packet with ack number 0
            print("ACK Scan Detected")
            scan_counts["ACK"] += 1
        
        if TCP in pkt and pkt[TCP].flags == "SF":  # check for SYN (0x01) and FIN (0x04) flags
            print("TCP packet with SYN and FIN flags detected")
            scan_counts["SYNFIN"] += 1

        if TCP in pkt and pkt[TCP].flags == 0: #check for null
            print("Null scan")
            scan_counts["NULL"] += 1

if __name__ == "__main__":


    # Replace 'pcap_file' with the path to your pcap file
    pcap_file = '/home/khattak01/Desktop/thesis/tests/packets-1000.pcap'

    # Open the pcap file using PcapReader
    with PcapReader(pcap_file) as pcap_reader:
        # Loop through packets
        for packet in pcap_reader:
            if 'IP' in packet:
                detect_scan(packet)
                # detect_scan(extract_packet_info(packet))
                # extract_packet_info(packet)

    print("-----------------------------------------------------------------------------------------------------------------------")
    print(error_packets)
    print("-----------------------------------------------------------------------------------------------------------------------")
    print("scan_counts >>> ",scan_counts)