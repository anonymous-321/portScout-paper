

import json

file_path = "/home/khattak01/Desktop/thesis/dataset/dst_ports_counts.json"
from nmap_top_ports import top_tcp_ports


# Open the JSON file and load its contents
with open(file_path, "r") as json_file:
    data = json.load(json_file)

# Now 'data' contains the contents of the JSON file
print(len(data))

# Filter ports that are not in the excluded list using a for loop
filtered_ports = set()
for port, count in data.items():
    if int(port) not in top_tcp_ports and count >= 2000:
        filtered_ports.add(int(port))

# print
print(filtered_ports)
print(len(filtered_ports))

# print(len(filtered_ports))