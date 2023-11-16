from scapy.all import PcapReader, wrpcap

def extract_and_save_packets(input_file_path, output_file_path, num_packets):
    try:
        extracted_packets = []

        # Open the pcap file using PcapReader
        with PcapReader(input_file_path) as pcap_reader:
            # Read the first 'num_packets' packets
            for idx, packet in enumerate(pcap_reader):
                extracted_packets.append(packet)

                # Process or print information about the extracted packet
                print(f"Packet {idx + 1}:")
                print(packet.summary())
                print("\n" + "=" * 50 + "\n")  # Separator for better readability

                # Break the loop when the desired number of packets is reached
                if idx + 1 == num_packets:
                    break

            print(f"Successfully extracted {len(extracted_packets)} packets.")

            # Save the extracted packets to a new pcap file
            wrpcap(output_file_path, extracted_packets)
            print(f"Extracted packets saved to {output_file_path}")

    except Exception as e:
        print(f"Error: {e}")

# Replace 'your_input_file.pcap' and 'your_output_file.pcap' with the actual paths
num_packets_to_extract = 10000
input_file_path = '/home/khattak01/Desktop/thesis/dataset/BenignTraffic/BenignTraffic3.pcap'
output_file_path = f'packets-{num_packets_to_extract}-4.pcap'

extract_and_save_packets(input_file_path, output_file_path, num_packets_to_extract)
