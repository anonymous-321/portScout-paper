from scapy.all import PcapReader
from scapy.all import *
from datetime import datetime

THRESHOLD = 50
timeout = 30  # 30 seconds
tracker = []

# Define the format_packet_data function
def extract_packet_data(packet):
    try:
        src_ip = dst_ip = tcp_flags = ""
        protocol = "Unknown"  # Default protocol

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            tcp_flags = packet[TCP].sprintf('%flags%')

        elif UDP in packet:
            protocol = "UDP"

        elif ICMP in packet:
            protocol = "ICMP"

        timestamp = float(packet.time)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "tcp_flags": tcp_flags,
            "timestamp": timestamp,
        }
    except Exception as e:
        print(f"Error extracting packet data: {e}")
        return False

def process_packet(packet):
    global tracker

    packet_data = extract_packet_data(packet)

    if not packet_data:
        return

    if (packet_data['protocol'] == "TCP" and packet_data['tcp_flags'] == "S") or packet_data['protocol'] == "UDP" or packet_data['protocol'] == "ICMP":
        print(packet_data)
        print("----------------------------------------------------------")

        counter = ""
        if packet_data['protocol'] == "TCP" and packet_data['tcp_flags'] == "S":
            counter = "tcp_counter"
        elif packet_data['protocol'] == "UDP":
            counter = "udp_counter"
        elif packet_data['protocol'] == "ICMP":
            counter = "icmp_counter"

        connection_found = False

        for conn in tracker:
            if conn['src_ip'] == packet_data['src_ip'] and conn['dst_ip'] == packet_data['dst_ip']:
                conn[counter] += 1
                connection_found = True

                if conn['tcp_counter'] > THRESHOLD or conn['udp_counter'] > THRESHOLD or conn['icmp_counter'] > THRESHOLD:
                    # Counter has reached or exceeded the threshold
                    print("Alert >>> ", conn)
                    print("Set a flow entry to drop packets from the attacker", packet_data['src_ip'], "  >>> ", packet_data['dst_ip'])

        if not connection_found:
            # New connection
            new_connection = {
                'src_ip': packet_data['src_ip'],
                'dst_ip': packet_data['dst_ip'],
                'protocol': packet_data['protocol'],
                'timestamp': packet_data['timestamp'],
                'tcp_counter': 0,
                'udp_counter': 0,
                'icmp_counter': 0,
            }
            new_connection[counter] = 1  # Initialize the correct counter

            tracker.append(new_connection)

    # Calculate the current time
    current_time = datetime.now().timestamp()

    # Filter and update tracked connections based on timeout
    new_tracked_connections = []
    for conn in tracker:
        if current_time - conn["timestamp"] <= timeout:
            new_tracked_connections.append(conn)

    tracker = new_tracked_connections

if __name__ == "__main__":
    # Replace 'pcap_file' with the path to your pcap file
    pcap_file = '/home/khattak01/Desktop/thesis/tests/packets-10000.pcap'

    # Open the pcap file using PcapReader
    with PcapReader(pcap_file) as pcap_reader:
        # Loop through packets
        for packet in pcap_reader:
            process_packet(packet)

    print("len(tracker) >>>", len(tracker))
    print("tracker >>>", tracker)
