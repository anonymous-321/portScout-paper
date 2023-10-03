from scapy.all import PcapReader, send
from collections import defaultdict
from datetime import datetime, timedelta

# Define parameters
time_interval = timedelta(seconds=30)
threshold = 0.8

# Create dictionaries to store flow counts and anomalous IPs
flow_counts = defaultdict(int)
anomalous_ips = set()

# Define the format_packet_data function
def format_packet_data(src_ip, dst_ip, src_port, dst_port, protocol, timestamp):
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "timestamp": timestamp,
    }

def process_packet(packet):
    # Process flow-level data
    timestamp, src_ip, dst_ip, src_port, dst_port, protocol, flow = packet
    timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

    # Calculate the current time minus the time interval
    current_time = timestamp
    start_time = current_time - time_interval

    # Update flow counts based on the flow direction and time interval
    if flow == "incoming" and timestamp >= start_time:
        flow_counts[src_ip] += 1
    elif flow == "outgoing" and timestamp >= start_time:
        flow_counts[dst_ip] += 1

# After processing packets as described above

# # Calculate the flow ratio for each IP within the last 30 seconds
# for ip, count in flow_counts.items():
#     if count > 0:  # Only consider IPs with flows in the last 30 seconds
#         flow_ratio = count
#         if flow_ratio > threshold:
#             anomalous_ips.add(ip)

# # Print anomalous IPs
# if anomalous_ips:
#     print("Anomalous IPs:")
#     for ip in anomalous_ips:
#         print(ip)
# else:
#     print("No anomalous IPs detected.")



if __name__ == "__main__":


    # Replace 'pcap_file' with the path to your pcap file
    pcap_file = '/home/khattak01/Desktop/thesis/tests/packets-500.pcap'

    packets_list = []

    # Open the pcap file using PcapReader
    with PcapReader(pcap_file) as pcap_reader:
        # Loop through packets
        for packet in pcap_reader:
            if 'IP' in packet:
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst

                # Check if both source and destination IPs start with "192.168.137."
                if src_ip.startswith("192.168.137.") and dst_ip.startswith("192.168.137."):
                    pass

                elif src_ip.startswith("192.168.137."):
                    packet.flow = "outgoing"
                
                elif dst_ip.startswith("192.168.137."):
                    packet.flow = "incoming"
            
            packets_list.append(packet)
    print(packets_list[2])


# Define the function to extract packet information
def extract_packet_info(packet):
    try:
        # Check if the packet is an Ethernet frame (Ether)
        if Ether in packet:
            packet = packet[IP]  # Extract the IP layer from the Ethernet frame

        src_ip = packet.src
        dst_ip = packet.dst
        src_port = None
        dst_port = None
        flags = None
        protocol = "Unknown"

        if TCP in packet:
            flags = packet[TCP].flags
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif SCTP in packet:
            protocol = "SCTP"
            src_port = packet[SCTP].sport
            dst_port = packet[SCTP].dport

        timestamp = packet.time

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": flags,
            "protocol": protocol,
            "timestamp": timestamp
        }
    except Exception as e:
        print("-----------------------------------------------------------------------------------------------------------------------")
        print(f"Error extracting packet information: {str(e)}")
        print("-----------------------------------------------------------------------------------------------------------------------")
        error_packets+=1
        return None
    