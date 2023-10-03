import concurrent.futures
import time
import threading


# Global ThreadPoolExecutor with 10 worker threads
executor_10 = concurrent.futures.ThreadPoolExecutor(max_workers=10)

def process_remove_packet(packet):
    print("---------------------------process_remove_packeprocess_remove_packet---------------------------")
# Function for remove_entries
def remove_entries():
    # Your code for remove_entries function
    
    list = ['192.168.94.237_64.233.184.188_5228_5228_TCP_A_1690138299.781521','192.168.94.237_64.233.184.188_5228_5228_TCP_A_1690138299.781521','192.168.94.237_64.233.184.188_5228_5228_TCP_A_1690138299.781521','192.168.94.237_64.233.184.188_5228_5228_TCP_A_1690138299.781521','192.168.94.237_64.233.184.188_5228_5228_TCP_A_1690138299.781521', '64.233.184.188_192.168.94.237_5228_5228_TCP_A_1690138300.043239', '192.168.94.237_224.0.0.251_5353_5353_UDP_0_1690138303.646697', '192.168.94.237_35.186.194.58_58924_443_TCP_A_1690138313.94534', '192.168.94.237_13.67.9.5_55438_443_TCP_A_1690138313.946552', '192.168.94.237_13.67.9.5_55450_443_TCP_A_1690138313.94865', '35.186.194.58_192.168.94.237_443_58924_TCP_A_1690138314.012793', '192.168.94.237_18.64.141.49_40446_443_TCP_A_1690138314.01628', '18.64.141.49_192.168.94.237_443_40446_TCP_A_1690138314.085244', '13.67.9.5_192.168.94.237_443_55450_TCP_A_1690138314.088617', '13.67.9.5_192.168.94.237_443_55450_TCP_A_1690138314.206569']
    
    # Submit tasks to the executor for each item in the list
    futures = [executor_10.submit(process_remove_packet, item) for item in list]

    # Wait for all tasks to complete
    concurrent.futures.wait(futures)
    print("Removing entries...")


    # Schedule the next execution of process_list after 2 seconds
    # threading.Timer(2, remove_entries).start()
    # time.sleep(2)


# Global ThreadPoolExecutor with 30 worker threads
executor_30 = concurrent.futures.ThreadPoolExecutor(max_workers=30)

t = 0

def check_packet(item,tmp_list):
    print(item)
    print(tmp_list)
    # t = tmp_list
    # t.append(item)
    # t = t+1
    return t
# Function for check_conditions
def check_conditions():
    # Your code for check_conditions function
    list = ['192.168.94.237_64.233.184.188_5228_5228_TCP_A_1690138299.781521', 
            '64.233.184.188_192.168.94.237_5228_5228_TCP_A_1690138300.043239', 
            '192.168.94.237_224.0.0.251_5353_5353_UDP_0_1690138303.646697', 
            '192.168.94.237_35.186.194.58_58924_443_TCP_A_1690138313.94534', 
            '192.168.94.237_13.67.9.5_55438_443_TCP_A_1690138313.946552', 
            '192.168.94.237_13.67.9.5_55450_443_TCP_A_1690138313.94865', 
            '35.186.194.58_192.168.94.237_443_58924_TCP_A_1690138314.012793', 
            '192.168.94.237_18.64.141.49_40446_443_TCP_A_1690138314.01628', 
            '18.64.141.49_192.168.94.237_443_40446_TCP_A_1690138314.085244', 
            '13.67.9.5_192.168.94.237_443_55450_TCP_A_1690138314.088617', 
            '13.67.9.5_192.168.94.237_443_55450_TCP_A_1690138314.206569']
    

      # Submit tasks to the executor for each item in the list and get the futures
    futures = [executor_30.submit(check_packet, item,list) for item in list]

    # Wait for all tasks to complete and get the results
    for future in concurrent.futures.as_completed(futures):
        tmp_list = future.result()
        print("Received result:", tmp_list)

    print(t)
    print("Checking conditions...")
    # time.sleep(2)

while True:

    
    check_conditions()
    remove_entries()

    # Get the number of threads running in the current program
    num_threads = threading.active_count()

    print("Number of threads running:", num_threads)

    time.sleep(10)

















from util import *
# print(format_time(get_time()))


def check_ports_packets(packets):
    dst_ports = []

    for packet in packets:
        packet_port = packet.split('_')[3]
        if not len(dst_ports):
            dst_ports.append({'port': packet_port, 'packets': [packet]})
            # break
        else:
            # print(dst_ports)
            tmp = True
            for i in range(len(dst_ports)):
                t = []
                if dst_ports[i]['port'] == packet_port:
                    t = dst_ports[i]['packets']
                    t.append(packet)
                    dst_ports[i]['packets'] = t
                    tmp = False
                    break
            # else:
                # t = dst_ports[i]['packets']
                # t.append(packet)
            if tmp:
                dst_ports.append({'port': packet_port, 'packets': [packet]})
                # break

    print(dst_ports)               
    print(len(dst_ports))               
    return dst_ports


list = ['192.168.94.237_64.233.184.188_5228_5228', 
        '64.233.184.188_192.168.94.237_5228_5228', 
        '192.168.94.237_224.0.0.251_5353_5353', 
        '192.168.94.237_35.186.194.58_58924_443', 
        '192.168.94.237_13.67.9.5_55438_443',
        '192.168.94.237_13.67.9.5_55450_443', 
        '35.186.194.58_192.168.94.237_443_58924', 
        '192.168.94.237_18.64.141.49_40446_443', 
        '18.64.141.49_192.168.94.237_443_443',
        '18.64.141.49_192.168.94.237_443_443',
        '18.64.141.49_192.168.94.237_443_443',
        '18.64.141.49_192.168.94.237_443_443'
        '18.64.141.49_192.168.94.237_443_443',
        '18.64.141.49_192.168.94.237_443_4434']

# for p in list:
# check_ports_packets(list)
