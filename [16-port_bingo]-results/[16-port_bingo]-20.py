from scapy.all import PcapReader
from scapy.all import *
import json
import datetime

# from scans_traffic import files

threshold = 20
timeout = 30
pkt_processed = 0
anomalous_ips = set()

top_ports = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70,
    79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135,
    139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280,
    301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464,
    465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563,
    587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705,
    711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888,
    898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001,
    1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028,
    1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041,
    1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054,
    1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067,
    1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080,
    1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093,
    1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108,
    1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130,
    1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163,
    1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199,
    1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271,
    1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352,
    1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533,
    1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718,
    1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840,
    1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998,
    1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013,
    2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045,
    2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111,
    2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200,
    2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399,
    2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638,
    2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910,
    2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017,
    3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269,
    3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370,
    3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659,
    3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828,
    3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986,
    3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126,
    4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567,
    4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033,
    5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200,
    5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432,
    5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679,
    5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862,
    5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925,
    5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000,
    6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106,
    6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567,
    6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792,
    6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100,
    7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741,
    7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007,
    8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083,
    8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192,
    8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402,
    8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994,
    9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090,
    9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415,
    9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876,
    9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001,
    10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215,
    10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111,
    11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238,
    14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012,
    16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988,
    19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221,
    20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000,
    27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337,
    32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778,
    32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572,
    34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501,
    45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160,
    49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002,
    50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822,
    52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294,
    57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000,
    65129, 65389,

    # entries from the dataset
    47106, 36872, 40971, 38930, 40979, 34845, 43038, 40992, 32804, 43045, 47142, 
    32816, 38962, 55352, 55356, 51260, 55360, 45120, 67, 68, 49223, 38988, 57423, 
    47184, 36945, 32850, 51288, 47196, 43102, 45150, 59489, 32871, 61546, 43117, 
    39024, 41073, 34929, 57459, 123, 39036, 51325, 55420, 55427, 39044, 37000, 57480, 
    45195, 55435, 41105, 37010, 55443, 55444, 39064, 47257, 51358, 32932, 47276, 59572, 
    34998, 39105, 41156, 41159, 49354, 49359, 32984, 49369, 32986, 32987, 47325, 57566, 
    47330, 32994, 232, 39148, 35054, 41206, 59654, 33039, 55570, 43286, 39193, 37154, 
    33060, 39216, 41267, 35130, 39227, 41279, 41280, 59717, 45382, 41287, 53577, 39243, 
    43341, 4431, 53586, 55639, 33112, 41308, 63842, 55658, 51564, 47475, 33140, 43382, 
    57722, 41338, 63867, 63868, 45439, 41343, 47491, 59780, 59779, 53638, 35208, 43401, 
    4500, 53658, 53661, 41373, 37285, 43433, 53681, 43444, 53686, 37303, 57782, 41399, 
    43450, 33211, 53696, 43456, 41431, 51673, 25050, 45537, 33252, 51689, 33264, 39409, 
    49658, 41469, 45578, 39435, 53772, 53776, 47635, 53782, 53785, 49700, 45606, 41522, 
    59957, 59958, 39479, 35381, 47674, 59966, 43589, 37446, 57926, 43592, 35401, 49738, 
    35403, 49742, 43598, 64086, 45661, 8802, 49772, 43632, 53873, 43637, 33397, 35454, 
    43649, 43652, 43653, 47754, 41611, 53920, 55972, 43687, 33448, 39591, 39598, 60080, 
    51888, 8883, 33460, 8886, 49849, 55998, 51904, 58049, 56003, 47811, 37573, 39631, 45787, 
    41698, 41708, 35570, 37618, 51976, 58122, 33547, 43790, 51988, 49947, 45855, 41760, 52001, 52003, 58153, 41770, 39724, 39726, 33584, 47929, 58171, 52028, 49979, 58189, 60251, 58213, 45931, 43884, 52080, 52081, 54131, 43893, 43894, 39798, 64382, 39807, 48003, 37764, 41861, 43924, 54167, 41880, 60313, 48028, 39841, 56227, 41892, 43943, 60329, 45997, 52145, 54228, 43993, 54236, 60383, 48111, 56305, 41977, 35841, 54273, 39941, 41990, 46091, 46092, 42000, 39961, 60446, 52262, 33831, 44076, 37933, 58418, 35898, 50235, 33867, 42060, 48206, 52306, 58450, 56404, 35926, 52316, 58469, 58470, 5223, 42090, 5228, 54380, 33929, 56458, 52384, 36008, 33961, 52394, 38061, 36027, 56509, 46269, 56513, 40135, 60618, 42189, 33997, 48335, 34006, 56534, 46299, 38108, 42204, 54494, 34014, 38119, 38120, 5353, 34029, 36081, 48370, 34037, 38135, 60664, 40186, 54523, 34044, 34045, 56582, 34065, 40214, 50456, 44313, 60698, 58648, 40220, 36125, 56606, 34083, 56611, 34099, 56632, 44344, 38200, 60731, 38202, 54591, 34115, 50502, 44359, 46408, 44362, 42320, 42321, 46423, 56675, 32100, 54627, 42346, 56700, 44417, 52614, 60809, 44429, 56718, 34189, 3478, 44439, 54686, 42400, 52644, 58804, 46518, 60858, 60859, 60862, 52671, 48584, 40395, 60879, 56807, 48618, 46572, 58862, 34287, 56814, 46577, 40434, 36356, 34344, 36394, 36405, 40508, 54853, 46662, 56912, 42577, 56915, 52821, 46681, 56925, 46686, 46690, 52836, 50798, 46706, 54900, 38518, 52858, 48765, 36477, 34435, 34458, 42652, 46750, 42672, 46770, 44725, 46782, 44736, 59075, 40648, 59091, 42710, 59099, 34529, 50920, 42737, 55028, 36598, 44796, 38657, 44804, 34567, 40711, 61195, 36620, 59151, 44816, 50971, 42783, 44832, 34602, 42797, 42798, 46893, 46896, 36660, 46907, 44860, 57152, 42817, 40770, 57155, 8006, 59211, 46924, 40779, 59225, 1883, 57180, 59229, 38755, 36712, 36716, 10101, 42875, 55177, 53130, 55186, 36768, 49066, 57263, 34737, 42937, 59337, 55245, 53199, 36828, 4070, 42985, 57324, 42988, 36844, 57327, 42999, 51194
]

# print(len(top_ports))

json_file = "/home/khattak01/Desktop/thesis/dataset/dst_ports_counts.json"

try:
    with open(json_file, 'r') as file:
        data = json.load(file)

    # Extract port numbers from the JSON data
    new_ports = [int(port) for port in data.keys()]

    # Verify and add only unique port numbers to the existing list
    for port in new_ports:
        if port not in top_ports:
            top_ports.append(port)

except FileNotFoundError:
    print(f"The file {json_file} was not found.")
except json.JSONDecodeError:
    print(f"There was an error decoding the JSON file: {json_file}")

# print(len(top_ports))

def get_time():
  return datetime.datetime.now().timestamp()

current_file_name = ""

def update_alert_ips(ip):
    # Load existing data from the JSON file if it exists
    json_file_path = 'alert_ips-20.json'
    try:
        with open(json_file_path, 'r') as json_file:
            data = json.load(json_file)
    except FileNotFoundError:
        data = []

    # Add the new IP and current time to the data
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_entry = {'ip': ip, 'time': timestamp,"file":current_file_name}
    data.append(new_entry)

    # Save the updated data to the JSON file
    with open(json_file_path, 'w') as json_file:
        json.dump(data, json_file, indent=2)
        print(f"Alert IP {ip} saved with timestamp {timestamp} to {json_file_path}")

tracked_connections = []

# Define the format_packet_data function
def extract_packet_data(packet):
    try:
        src_ip = dst_ip = dst_port = ""
        # packet.show()

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        if not TCP in packet:
            return False
        
        dst_port = packet[TCP].dport

        
        timestamp = datetime.datetime.now().timestamp()
        # print("timestamp",timestamp)
        # date_time = datetime.utcfromtimestamp(timestamp)

        # # If you want to display the date and time in a specific format, you can use strftime
        # formatted_date_time = date_time.strftime('%Y-%m-%d %H:%M:%S.%f')

        # print("Proper Date and Time:", formatted_date_time)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "timestamp": timestamp,
        }   
    except Exception as e:
        print(f"Error extracting packet data: {e}")
        return -1


# tmp = 0
def process_packet(packet):
    # global tmp

    global tracked_connections

    global pkt_processed
    pkt_processed = pkt_processed + 1 

    if pkt_processed % 10000 == 0:
        print("pkt_processed >>> ", pkt_processed)
        print("----------------------------------------------------------") 

    packet = extract_packet_data(packet)

    if not packet:
        return
    
    pkt_src_ip = packet['src_ip']
    if pkt_src_ip in anomalous_ips:
        return


    if packet['dst_port'] not in top_ports:
        return False

    # Calculate the current time
    current_time = datetime.datetime.now().timestamp()

    #Filter and update tracked connections based on timeout

    tracked_connections = [conn for conn in tracked_connections if (current_time - conn["timestamp"] <= timeout)]


    # Check if the packet's connection exists
    # found_flg = False
    for conn in tracked_connections:
        if conn['src_ip'] == packet['src_ip'] and conn['dst_ip'] == packet['dst_ip']:

            if packet['dst_port'] not in conn['set_of_dst_ports']:
                conn['set_of_dst_ports'].append(packet['dst_port'])
                # found_flg = True

            conn['timestamp'] = packet['timestamp']
            
            if len(conn['set_of_dst_ports']) >= threshold:
                # set_of_dst_ports has reached or exceeded the threshold
                anomalous_ips.add(pkt_src_ip)
                update_alert_ips(pkt_src_ip)
                print("Alert >>> Scanning", conn)

            break
    else:#else block will execute when the for loop completes its iteration without encountering a break statement.
        # If no existing connection is found, create a new one
    # if not found_flg:
        new_connection = {
            'src_ip': packet['src_ip'],
            'dst_ip': packet['dst_ip'],
            'set_of_dst_ports': [packet['dst_port']],
            'timestamp': packet['timestamp']
        }
        tracked_connections.append(new_connection)
    

    # print(len(packets))
    # print(packet)
    # print("----------------------------------------------------------")

if __name__ == "__main__":


    # Replace 'pcap_file' with the path to your pcap file
    # files = ['/home/khattak01/Desktop/port-scanning-detection-paper-main/dataset/scans-traffic/filtered-traffic/ubuntu-traffic/simple-scans-modified-traffic/filtered_nmap_top-ports_tcp-syn-.pcap',
    #          "/home/khattak01/Desktop/port-scanning-detection-paper-main/dataset/scans-traffic/filtered-traffic/window-traffic/simple-scans-modified/filtered_nmap_top-ports-tcp-syn.pcap"]

    files = [
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic1.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic2.pcap',
        '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap'
    ]

    # Record the start time
    start_time = time.time()

    for file in files:
        tracked_connections = []
        current_file_name = file
        # Open the pcap file using PcapReader
        current_pkt_time = 0
        prev_pkt_time = 0
        time_taken_by_process = 0
        with PcapReader(file) as pcap_reader:
            # Loop through packets
            for packet in pcap_reader:
                prev_pkt_time = current_pkt_time
                current_pkt_time = packet.time
                time_diff = current_pkt_time - prev_pkt_time - time_taken_by_process
                     
                # Ensure time_diff is non-negative
                time_diff = max(0, time_diff)
                # print(time_diff)
                # Check if prev_pkt_time is not zero before sleeping
                if prev_pkt_time != 0:
                    time.sleep(float(time_diff))
                        # Measure the time taken by process_packet
                start_time_p = time.time()
                process_packet(packet)
                end_time_p = time.time()

                # Calculate the time taken by process_packet
                time_taken_by_process = end_time_p - start_time_p
            print(current_file_name,"Done!")
    # Record the end time
    end_time = time.time()
    # Calculate the time taken
    time_taken = end_time - start_time

    print(f"Time taken: {time_taken} seconds") 

    
