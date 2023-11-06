from .. import tcp_syn
from .. import tcp_connect
from .. import tcp_null
from .. import tcp_fin
from .. import tcp_xmas
from .. import tcp_ack
from .. import tcp_maimon
from .. import tcp_custom_scan

import random

target_ip = '192.168.18.179'

# Function to randomly select and run one of the functions
def random_scan_function(port):
    random_value = random.randint(1, 8)
    print("random_value >>> ",random_value)
    if random_value == 1:
        tcp_syn(target_ip, port)
    elif random_value == 2:
        tcp_connect(target_ip, port)
    elif random_value == 3:
        tcp_null(target_ip, port)
    elif random_value == 4:
        tcp_fin(target_ip, port)
    elif random_value == 5:
        tcp_xmas(target_ip, port)
    elif random_value == 6:
        tcp_ack(target_ip, port)
    elif random_value == 7:
        tcp_maimon(target_ip, port)
    elif random_value == 8:
        tcp_custom_scan(target_ip, port)
    print("-----------------------------------------------")