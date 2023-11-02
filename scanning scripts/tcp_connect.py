import socket

#The first two steps (SYN and SYN/ACK) are exactly the same as with a SYN scan. Then, instead of aborting the half-open connection with a RST packet, 
# attacker acknowledges the SYN/ACK with its own ACK packet, completing the connection. In this case
def tcp_connect(target_ip, target_port):
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout for the connection attempt
        sock.settimeout(1)
        
        # Attempt to connect to the target
        result = sock.connect_ex((target_ip, target_port,))
        
        # Check the result of the connection attempt
        if result == 0:
            print(f"Port {target_port} is open")
        # else:
        #     print(f"Port {target_port} is closed")
        
        # Close the socket
        sock.close()
    
    except KeyboardInterrupt:
        print("Scan aborted.")
    except socket.error:
        print("Could not connect to the target.")