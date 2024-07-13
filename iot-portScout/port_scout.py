import socket
import struct

import datetime
import json

import subprocess
import time
import threading

PORT_THRESHOLD = 40
TIME_THRESHOLD = 30

anomalous_ips = set()

packets = []

# pkt_processed = 0

def format_time(timestamp):
  # Convert the timestamp to a datetime object
  return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

def get_time():
  return datetime.datetime.now().timestamp()

def update_alert_ips(ip):
    # Load existing data from the JSON file if it exists
    json_file_path = 'iot_alert_ips-40.json'
    try:
        with open(json_file_path, 'r') as json_file:
            data = json.load(json_file)
    except FileNotFoundError:
        data = []

    # Add the new IP and current time to the data
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_entry = {'ip': ip, 'time': timestamp,"file":json_file_path}
    data.append(new_entry)

    # Save the updated data to the JSON file
    with open(json_file_path, 'w') as json_file:
        json.dump(data, json_file, indent=2)
        print(f"Alert IP {ip} saved with timestamp {timestamp} to {json_file_path}")


def ip_to_str(ip):
    return '.'.join(map(str, ip))

def parse_ip_header(raw_data):
    ip_header = raw_data[14:34]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    protocol = iph[6]
    src_ip = ip_to_str(iph[8])
    dst_ip = ip_to_str(iph[9])
    return protocol, iph_length, src_ip, dst_ip

def parse_tcp_header(raw_data, iph_length):
    tcp_header = raw_data[14 + iph_length:14 + iph_length + 20]
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    dst_port = tcph[1]
    return dst_port

def parse_udp_header(raw_data, iph_length):
    udp_header = raw_data[14 + iph_length:14 + iph_length + 8]
    udph = struct.unpack('!HHHH', udp_header)
    dst_port = udph[1]
    return dst_port

def block_ip_temporarily(ip_address):
    try:
        # Add iptables rule to block the IP
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
        print(f"Blocked IP {ip_address} temporarily.")

        # Wait for specified time (60 seconds)
        time.sleep(60)

        # Remove iptables rule to unblock the IP
        subprocess.run(['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
        print(f"Unblocked IP {ip_address} after 60 seconds.")

    except subprocess.CalledProcessError as e:
        print(f"Error blocking/unblocking IP {ip_address}: {e}")

def check_packet(srcIP,dstIP,dstPort):

    global packets, anomalous_ips

    for pkt in packets:
        if pkt['src_ip']==srcIP and pkt['dst_ip']==dstIP:

            if get_time() - pkt['timestamp'] >= TIME_THRESHOLD:
                packets.remove(pkt)

            # packets = [p for p in packets if (get_time() - p["timestamp"] <= TIME_THRESHOLD)]

            # if len(pkt['dst_ports']) == 0:
            #     packets.append({"src_ip":srcIP,"dst_ip":dstIP,"dst_ports":[dstPort],"timestamp":get_time()})

            if len(pkt['dst_ports']) > PORT_THRESHOLD:
                dst_ip = pkt['src_ip']
                anomalous_ips.add(dst_ip)
                update_alert_ips(dst_ip)
                print("alert IP : ", dst_ip, "time : ", format_time(get_time()))

                 # Block the IP temporarily in a separate thread
                # threading.Thread(target=block_ip_temporarily, args=(pkt['src_ip'],)).start()


            if dstPort not in pkt['dst_ports']:
                pkt['dst_ports'].append(dstPort)

            # else:
            #     packets.append({"src_ip":srcIP,"dst_ip":dstIP,"dst_ports":[],"timestamp":get_time()})
            break
    else:
        packets.append({"src_ip":srcIP,"dst_ip":dstIP,"dst_ports":[dstPort],"timestamp":get_time()})



def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    conn.bind(('ens33', 0))  # Replace 'ens33' with your network interface

    while True:
        raw_data, addr = conn.recvfrom(65535)
        
        eth_proto, = struct.unpack('!H', raw_data[12:14])
        if eth_proto == 0x0800:  # IPv4
            protocol, iph_length, src_ip, dst_ip = parse_ip_header(raw_data)

            if dst_ip.startswith('192.168.72') and (protocol == 6 or protocol == 17):  # TCP or UDP
                if protocol == 6:  # TCP
                    dst_port = parse_tcp_header(raw_data, iph_length)
                    print(f'TCP Packet - Src IP: {src_ip}, Dst IP: {dst_ip}, Dst Port: {dst_port}')

                    check_packet(src_ip,dst_ip,dst_port)

                    # packets.append({"src_ip":src_ip,"dst_ip":dst_ip,"dst_port":dst_port,"timestamp":get_time()})

                elif protocol == 17:  # UDP
                    dst_port = parse_udp_header(raw_data, iph_length)
                    print(f'UDP Packet - Src IP: {src_ip}, Dst IP: {dst_ip}, Dst Port: {dst_port}')

                    check_packet(src_ip,dst_ip,dst_port)
                    
                    # packets.append({"src_ip":src_ip,"dst_ip":dst_ip,"dst_port":dst_port,"timestamp":get_time()})

        print("len(packets) : ", len(packets))

if __name__ == '__main__':
    main()
