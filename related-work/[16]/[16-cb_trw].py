from scapy.all import PcapReader
from scapy.all import *

THRESHOLD = 40
tracker = []

# Define the format_packet_data function
def extract_packet_data(packet):
    try:
        src_ip = dst_ip = ""
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if TCP not in packet:
            return False
        
        # Access the TCP flags and create a string representation
        # flags = []

        # if packet[TCP].flags & TCP.flags.S:
        #     flags.append('A')
        # if packet[TCP].flags & TCP.flags.A:
        #     flags.append('A')

        tcp_flags = packet[TCP].sprintf('%flags%')
        
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "tcp_flags": tcp_flags,
        }   
    except Exception as e:
        print(f"Error extracting packet data: {e}")
        return False

def process_packet(packet):
    global tracker


    packet = extract_packet_data(packet)

    # print(packet)
    # print("----------------------------------------------------------")
    
    if not packet:
        return
    
    if packet['tcp_flags']=="SA" or packet['tcp_flags']=="S":
        print(packet)
        print("----------------------------------------------------------")
        if packet['tcp_flags'] == 'S':  # Packet is SYN
            connection_found = False

            for conn in tracker:
                if conn['src_ip'] == packet['src_ip'] and conn['dst_ip'] == packet['dst_ip']:
                    conn['counter'] += 1
                    connection_found = True

                    if conn['counter'] < THRESHOLD:
                        # Counter is below the threshold, do nothing
                        pass
                    else:
                        # Counter has reached or exceeded the threshold
                        print("Alert >>> ", conn)
                        print("Set a flow entry to drop packets from the attacker", packet['src_ip'], "  >>> ",packet['dst_ip'])

            if not connection_found:
                # New connection
                new_connection = {
                    'src_ip': packet['src_ip'],
                    'dst_ip': packet['dst_ip'],
                    'counter': 1,
                }
                tracker.append(new_connection)

        else:  # Packet is not SYN
            # connection_found = False

            for conn in tracker:
                if conn['src_ip'] == packet['src_ip'] and conn['dst_ip'] == packet['dst_ip']:
                    conn['counter'] -= 1
            #         connection_found = True

            # if not connection_found:
            #     # New connection (this should not happen for SYN-ACK packets)
            #     pass



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
