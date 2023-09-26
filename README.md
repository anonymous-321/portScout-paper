Network Packet Sniffer with Anomaly Detection
=============================================

This Python script is designed to capture network packets from the specified network interface and perform anomaly detection on the captured packets. The script uses the 'scapy' library for packet capturing and 'concurrent.futures' for multi-threading.

Requirements:
-------------
- Python 3.x
- scapy library (install using 'pip install scapy')
- concurrent.futures (usually comes with the Python standard library)

Usage:
------
1. Make sure you have the required dependencies installed.
2. Modify the 'interface' variable in the 'packet_sniffer()' function to specify the network interface to capture packets from.
3. Run the script with Python:
    ```
    python packet_sniffer.py
    ```
4. The packet sniffer will start capturing network traffic. It will continue to run until the program is interrupted (Ctrl+C).
5. The captured packets are processed to extract header information for TCP and UDP packets with the IP layer.
6. Anomaly detection is performed based on destination ports and time differences between captured packets.

Functions:
----------
1. `insert_packet(packet)`: Inserts the given packet into the 'packets' list.
2. `delete_packet(packet)`: Deletes the given packet from the 'packets' list if its timestamp difference is greater than the DELETE_TIME_THRESHOLD.
3. `remove_entries()`: Removes packets from the 'packets' list whose timestamp difference exceeds the DELETE_TIME_THRESHOLD.
4. `save_scanner_data(packet)`: Saves the packet in the 'scanner_packets' dictionary based on its source IP address.
5. `check_ports_packets(packet)`: Checks the destination ports in packets and groups them based on port numbers in the 'dst_ports' list. Triggers a scanning alert if the number of packets for a port exceeds PORT_THRESHOLD.
6. `process_packet(packet)`: Processes the captured packet and extracts header information for TCP and UDP packets with the IP layer.
7. `packet_sniffer()`: Starts the packet sniffer and captures network traffic using the specified network interface. Captured packets are processed by the `process_packet()` function.
8. `periodic_remove_entries()`: Calls the `remove_entries()` and `check_conditions()` functions periodically to manage the 'packets' list and 'scanner_packets' dictionary.

Scanning Alert:
---------------
If the number of packets for a specific destination port exceeds the PORT_THRESHOLD, a scanning alert will be triggered. This implies a potential scanning activity on the network.

Note:
-----
- The 'PORT_THRESHOLD', 'TIME_THRESHOLD', and 'DELETE_TIME_THRESHOLD' constants can be adjusted to fine-tune the anomaly detection parameters.
- The script uses multi-threading for better performance. The number of worker threads can be modified in 'executor_20' and 'executor_60' as needed.
- The 'wlp0s20f3' interface is set as the default capture interface. Ensure that this interface is correct for your system.

