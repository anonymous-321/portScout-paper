# Define the parameters for the proposed method
threshold = 0.5
window_size = 10
anomaly_threshold = 2.0

# Initialize the variables
packet_in_count = 0
packet_in_rate = 0
packet_in_rate_history = []
anomaly_detected = False

# Listen for Packet-In messages from the OpenFlow switch
while True:
    packet_in = listen_for_packet_in()

    # Update the packet-in count and rate
    packet_in_count += 1
    packet_in_rate = packet_in_count / window_size

    # Add the current packet-in rate to the history
    packet_in_rate_history.append(packet_in_rate)

    # Check if an anomaly has been detected
    if len(packet_in_rate_history) >= window_size:
        mean_rate = sum(packet_in_rate_history) / window_size
        std_dev = statistics.stdev(packet_in_rate_history)
        if packet_in_rate > mean_rate + anomaly_threshold * std_dev:
            anomaly_detected = True

    # If an anomaly is detected, take action
    if anomaly_detected:
        block_port_scan()
        reset_variables()
        anomaly_detected = False

    # If the packet-in rate drops below the threshold, reset the variables
    if packet_in_rate < threshold:
        reset_variables()