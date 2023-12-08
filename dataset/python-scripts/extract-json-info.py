import json

# Load the JSON files generated earlier
with open('/home/khattak01/Desktop/thesis/dataset/src_ip_counts.json', 'r') as src_ip_file:
    src_ip_counts = json.load(src_ip_file)

with open('/home/khattak01/Desktop/thesis/dataset/dst_ip_counts.json', 'r') as dst_ip_file:
    dst_ip_counts = json.load(dst_ip_file)

with open('/home/khattak01/Desktop/thesis/dataset/src_ports_counts.json', 'r') as src_ports_file:
    src_ports_counts = json.load(src_ports_file)

with open('/home/khattak01/Desktop/thesis/dataset/dst_ports_counts.json', 'r') as dst_ports_file:
    dst_ports_counts = json.load(dst_ports_file)

# Extract the top 10 source IPs
top_src_ips = sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

# Extract the top 10 destination IPs
top_dst_ips = sorted(dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

# Extract the top source ports
top_src_ports = sorted(src_ports_counts.items(), key=lambda x: x[1], reverse=True)[:10]

# Extract the top destination ports
top_dst_ports = sorted(dst_ports_counts.items(), key=lambda x: x[1], reverse=True)[:10]

# Count unique source and destination IPs and ports
unique_src_ips_count = len(src_ip_counts)
unique_dst_ips_count = len(dst_ip_counts)
unique_src_ports_count = len(src_ports_counts)
unique_dst_ports_count = len(dst_ports_counts)

# Print the results
print("Top 10 Source IPs:")
for src_ip, count in top_src_ips:
    print(f"{src_ip}: {count} packets")

print("\nTop 10 Destination IPs:")
for dst_ip, count in top_dst_ips:
    print(f"{dst_ip}: {count} packets")

print("\nTop Source Ports:")
for src_port, count in top_src_ports:
    print(f"{src_port}: {count} packets")

print("\nTop Destination Ports:")
for dst_port, count in top_dst_ports:
    print(f"{dst_port}: {count} packets")

# Print counts of unique source and destination IPs and ports
print(f"\nUnique Source IPs Count: {unique_src_ips_count}")
print(f"Unique Destination IPs Count: {unique_dst_ips_count}")
print(f"Unique Source Ports Count: {unique_src_ports_count}")
print(f"Unique Destination Ports Count: {unique_dst_ports_count}")
