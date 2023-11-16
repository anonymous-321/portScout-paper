from scapy.all import *
from scapy.all import PcapReader
import threading
import psutil
import time

def process_pcap(pcap_file):
    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            # print(packet)
            packet_time = packet.time
            # print(f"Packet Time: {packet_time}")

def fun1():
    pcap_file = '/home/khattak01/Desktop/thesis/tests/packets-10000-1.pcap'
    process_pcap(pcap_file)

def fun2():
    pcap_file = '/home/khattak01/Desktop/thesis/tests/packets-10000-2.pcap'
    process_pcap(pcap_file)

def resource_monitor():
    while True:
        # Get CPU and memory usage
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_usage = psutil.virtual_memory().percent

        # Print the usage
        print(f"CPU Usage: {cpu_usage}% | Memory Usage: {memory_usage}%")

        # Sleep for a while to avoid continuous printing
        time.sleep(10)

pid = os.getpid()
print(pid)

# Create threads and start them
thread1 = threading.Thread(target=fun1)
thread2 = threading.Thread(target=fun2)
monitor_thread = threading.Thread(target=resource_monitor)

# Start the resource monitor thread
monitor_thread.start()

# Start the packet processing threads
thread1.start()
thread2.start()

# Wait for both threads to finish
thread1.join()
thread2.join()

# Stop the resource monitor thread
monitor_thread.join()

print("Main thread done.")

