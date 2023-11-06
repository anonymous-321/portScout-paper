from scapy.all import TCP, IP, sr1, RandShort, RandByte
import random

# Define a range for random ports (e.g., 1024-49151).
port_range = range(1024, 49152)
# Define a list of TCP flags and randomize their order.
flags = ["S", "A", "FSRPAU", "", "FPU","F"]


import time
import random

# Function to generate a random future timestamp
def generate_random_future_timestamp():
    current_time = int(time.time())
    # Generate a random offset between 0 and 60 seconds (adjust as needed)
    offset = random.randint(0, 600)
    custom_timestamp = current_time + offset
    return custom_timestamp

# Function to perform a TCP SYN scan with random attributes
def packet_manipulation(target_ip, target_port):
    try:
        # Generate a random source port from the defined range.
        source_port = random.choice(port_range)

        # Randomly select a flag from the list
        selected_flag = random.choice(flags)

        # Generate custom random window size (16-bit value)
        window_size = random.randint(1, 65535)
        
        # Generate custom random MSS (16-bit value)
        mss_value = random.randint(1, 65535)

        # # Create a custom timestamp value (32 bits)
        # timestamp_value = random.getrandbits(32)

        # Create the TCP SYN packet with the custom timestamp
        # custom_timestamp = generate_random_future_timestamp()   
        # print("timestamp_value >>> ",custom_timestamp)


        # Craft a TCP packet with custom time in the TCP header
        syn_packet = IP(dst=target_ip) / TCP(sport=source_port, dport=target_port, flags=selected_flag, window=window_size, options=[('MSS', mss_value)])

        # Send the packet and receive the response
        response = sr1(syn_packet, timeout=.5, verbose=0)

        # Check the response
        if response is not None and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN/ACK packet
                print(f"Port {target_port} is open")

    except KeyboardInterrupt:
        print("Scan aborted.")
    except Exception as e:
        print(f"Error: {str(e)}")
