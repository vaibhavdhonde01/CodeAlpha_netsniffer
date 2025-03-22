
# Network Sniffer

A simple network sniffer that captures and analyzes network packets using the Scapy library.

## Features

- Capture network packets (IP, TCP, UDP)
- Display packet details such as source and destination IP addresses, ports, protocol, and payload

## Prerequisites

- Python 3.x
- Scapy library

## Installation

1. Clone the repository:

    ```shell
    git clone https://github.com/yourusername/network-sniffer.git
    cd network-sniffer
    ```

2. Install the required dependencies:

    ```shell
    pip install scapy
    ```

## Usage

1. Ensure the specified network interface is active and has traffic.
2. Generate some network traffic by pinging a local machine or downloading a file.
3. Run the script with `sudo` to have the necessary permissions to capture network traffic:

    ```shell
    sudo python3 network_sniffer.py
    ```

4. Replace the source IP address in the script with the one you want to filter:

    ```python
    source_ip = '192.168.233.128'  # Replace with the source IP address you want to filter
    ```
