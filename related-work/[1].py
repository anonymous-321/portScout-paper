from collections import defaultdict
from datetime import datetime, timedelta

# Simulated flow-level data (timestamp, src_ip, dst_ip, src_port, dst_port, protocol)
data = [
    ("2023-09-27 12:00:00", "192.168.1.1", "192.168.2.1", 80, 12345, "TCP"),
    ("2023-09-27 12:01:00", "192.168.1.2", "192.168.2.2", 80, 54321, "TCP"),
    # Add more data...
]
def format_packet_data(src_ip, dst_ip, src_port, dst_port, protocol, timestamp):
    packet_data = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "timestamp": timestamp
    }
    return packet_data



# Define parameters
time_interval = timedelta(seconds=30)
threshold = 0.8

# Create dictionaries to store flow counts and anomalous IPs
# flow_counts = defaultdict(int)
incoming_packets = []
outgoing_packets = []

anomalous_ips = set()

def main(packet):
    # Process flow-level data
    timestamp, src_ip, dst_ip, src_port, dst_port, protocol = packet
    timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

    # Update flow counts
    if packet.flow == "incoming":
        incoming_packets.append(format_packet_data(src_ip,dst_ip,src_port,dst_port,protocol,timestamp))
    else:
        outgoing_packets.append(format_packet_data(src_ip,dst_ip,src_port,dst_port,protocol,timestamp))
        
    # Detect anomalous IPs
    for interval, ip in flow_counts:
        if interval == interval_start:
            generated_flows = flow_counts[(interval, src_ip)]
            received_flows = flow_counts[(interval, dst_ip)]
            if received_flows == 0 or generated_flows / received_flows > threshold:
                anomalous_ips.add(src_ip)

# Show anomalous IPs
print("Anomalous IPs:")
for ip in anomalous_ips:
    print(ip)
