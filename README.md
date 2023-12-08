# PortScout: A Novel Lightweight Approach to Detecting Port Scanning and Evasion Attacks

Welcome to the official repository for the source code, dataset, and experimental setup of our research paper titled "PortScout: A Novel Lightweight Approach to Detecting Port Scanning and Evasion Attacks." This repository contains all the essential components for reproducing our experiments and understanding the methodology presented in the paper.

## Contents

- **dataset:** This folder includes all the crucial data used in the evaluation, along with the dataset (scanning attack) created for experiments in pcap file format. The dataset folder also contains Python scripts used for data operations and attribute counting.

- **related-work:** Explore this folder to find the five methods discussed in the paper, which we use for comparison. The experimental code is available, allowing you to observe how each method was executed and how the system handled it.

- **results:** In this folder, you'll find different configurations of the methods we utilized, along with the experimental results for each configuration on every dataset tested. Results are stored in JSON files.

- **scanning-scripts:** The python scripts used for attack generation are housed in this folder. You can examine the details of every scan in these files.

- **traffic-filtration:** This folder contains Python scripts used to filter and modify the attack dataset according to our scenario. If you wish to use our dataset, these scripts can be employed to modify data according to your needs.

- **util:** Basic Python scripts for various repetitive tasks are stored in this folder.

- **tests:** Find Python code files in this folder that we used for testing parts of the code individually.

## Dependencies

The system has one dependency, which can be installed using the following command:

```bash
pip install scapy
