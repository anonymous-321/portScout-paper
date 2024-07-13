# PortScout: A Lightweight Approach to Detect Port Scanning Evasion Attacks

Welcome to the official repository for the source code, dataset, and experimental setup of our research paper titled "PortScout: A Novel Lightweight Approach to Detecting Port Scanning and Evasion Attacks." This repository contains all the essential components for reproducing our experiments and understanding the methodology presented in the paper.

## Contents

- **dataset:** Contains crucial data used in the evaluation, including the dataset (scanning attack) in pcap file format. Python scripts for data operations and attribute counting are also included.

- **related-work:** Provides implementations of five methods discussed in the paper for comparison. Explore the experimental code to observe each method's execution and system handling.

- **results:** Includes different method configurations and their experimental results on tested datasets, stored in JSON files.

- **scanning-scripts:** Python scripts used for generating attack scenarios.

- **traffic-filtration:** Python scripts for filtering and modifying the attack dataset based on specific scenarios.

- **util:** Basic Python scripts for various repetitive tasks.

- **tests:** Code files used for individual code testing.

- **iot_portScout:** Contains Python source code for deploying PortScout on Raspberry Pi for real-time environment evaluation.

## Dependencies

The system has one dependency, which can be installed using the following command:

```bash
pip install scapy
````

Feel free to explore the folders and utilize the provided resources to better understand our research and reproduce the results. If you have any questions or encounter issues, please don't hesitate to reach out.
