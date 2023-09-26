import socket

def udp_scan(target_ip, target_port):
    try:
        # Create a UDP socket
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Set a timeout for the receive operation
        udp_socket.settimeout(1)

        # Attempt to send data to the target port
        udp_socket.sendto(b"", (target_ip, target_port))

        # Receive a response
        data, addr = udp_socket.recvfrom(1024)
        # print(data)
        # print(addr)
        # If data is received, the port is considered open
        if data:
            print(f"Port {target_port} is open")
                
        # else:
        #     print(f"Port {target_port} is closed")


        # Close the socket
        udp_socket.close()

    except socket.timeout:
        # Handle the case where the socket times out (port is closed or filtered)
        pass
    except KeyboardInterrupt:
        print("Scan aborted.")
        return
    except Exception as e:
        print(f"Error: {str(e)}")

