from scapy.all import *
import datetime
import time

def get_time():
  return datetime.datetime.now().timestamp()


def read_pcap(file_path):
    current_pkt_time = 0
    prev_pkt_time = 0
    with PcapReader(file_path) as pcap_reader:
            for packet in pcap_reader:
                prev_pkt_time = current_pkt_time
                current_pkt_time = packet.time
                time_diff = current_pkt_time - prev_pkt_time
                
                # Check if prev_pkt_time is not zero before sleeping
                if prev_pkt_time != 0:
                    time.sleep(float(time_diff))
                # print("time_diff >>>", float(time_diff))
                # time.sleep(float(time_diff))
                # print("current_pkt_time >> ",current_pkt_time)
                # print("pre_pkt_time >>>", prev_pkt_time)


if __name__ == "__main__":
    pcap_file_path = '/home/khattak01/Desktop/thesis/tests/packets-10000.pcap'
    pcap_file_path = '/home/khattak01/Desktop/thesis/dataset/scans-traffic/filtered-traffic/ubuntu-traffic/evasion-technique-filtered-traffic/slow-scan/slow-scan-200ports-ramdom-pkts(20-30)-radom-delay1-10s.pcap'

    # Record the start time
    start_time = time.time()
    
    read_pcap(pcap_file_path)

    # Record the end time
    end_time = time.time()
    # Calculate the time taken
    time_taken = end_time - start_time

    print(f"Time taken: {time_taken} seconds") 
