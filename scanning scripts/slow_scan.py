from scapy.all import TCP,IP, sr1
import random
import time

from top_ports import top_tcp_ports

from concurrent.futures import ThreadPoolExecutor


target_ip = '192.168.18.179'


# Function to decide on the source port
def select_source_port():
    if random.choice([True, False]):  # Randomly choose between static and dynamic source port
        return random.randint(1024, 10000)  # Dynamic source port range
    else:
        return 100  # Static source port

def tcp_syn(target_ip, target_port):
    global current_time
    try:

        source_port = select_source_port()
        
        # Craft a TCP SYN packet with the TCP Timestamps option
        syn_packet = IP(dst=target_ip) / TCP(sport=source_port, dport=target_port, flags="S")

        # Send the packet and receive the response
        response = sr1(syn_packet, timeout=.3, verbose=0)

        # Check the response
        if response is not None and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN/ACK packet
                print(f"Port {target_port} is open")
                
    except KeyboardInterrupt:
        print("Scan aborted.")
    except Exception as e:
        print(f"Error: {str(e)}")

def scan_port(port):
    tcp_syn(target_ip,port)
    print("-----------------------------------------")

if __name__ == "__main__":

    # print(len(top_tcp_ports))
    # print(len(top_udp_ports))
    
    max_threads = 1  # Maximum number of threads

    # Randomly select 198 ports
    random_ports = set(random.sample(top_tcp_ports, 995))
    random_ports.add(3000)
    random_ports.add(5000)
    random_ports.add(8000)
    random_ports.add(8001)
    random_ports.add(8002)

    flg = 0
    random_number = random.randint(20, 30)
    # random_number = 5
    p = 0
    for port in random_ports:
        scan_port(port)
        flg += 1
        p+=1
        if flg%random_number==0:
            flg = 0
            random_number = random.randint(20, 30)

            random_delay = random.uniform(1, 10)
            
            print(f"Waiting for {random_delay:.2f} seconds...")
            print("ports scanned >>>",p)
            print(" random_number>>>",random_number)
            # Sleep for the random delay
            time.sleep(random_delay)



    # with ThreadPoolExecutor(max_threads) as executor:
    #     executor.map(scan_port, random_ports)