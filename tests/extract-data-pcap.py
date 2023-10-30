from scapy.all import PcapReader, PcapWriter

def extract_and_save_packets(input_pcap_file, output_pcap_file, num_packets=500):
    try:
        # Create a PcapReader for the input file
        input_cap = PcapReader(input_pcap_file)

        # Create a PcapWriter for the output file
        output_cap = PcapWriter(output_pcap_file)

        # Extract and save the first 'num_packets' packets
        packet_count = 0
        for packet in input_cap:
            if packet_count >= num_packets:
                break
            output_cap.write(packet)
            packet_count += 1

        # Close both input and output PCAP files
        input_cap.close()
        output_cap.close()

        print(f"{packet_count} packets extracted and saved to {output_pcap_file}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    # Example usage:
    # extract_and_save_packets("input.pcap", "output.pcap", num_packets=500)

    # Call the function to extract and save packets
    num_packets = 10000  # Specify the number of packets to extract (optional, default is 500)
    input_pcap_file = "/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic.pcap"  # Replace with the path to input PCAP file
    output_pcap_file = f"packets-{num_packets}.pcap"  # Replace with the desired path for the output PCAP file

    extract_and_save_packets(input_pcap_file, output_pcap_file, num_packets)
