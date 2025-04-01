# Network Packet Analyzer

This project is a simple network packet analyzer built using Python and the Scapy library. It captures network packets and displays information such as source IP, destination IP, protocol, and payload.

## Features

- Captures network packets in real-time.
- Displays detailed information about each packet, including:
  - Source IP address
  - Destination IP address
  - Protocol (TCP/UDP)
  - Payload

## Prerequisites

- Python 3.x installed on your system.
- The Scapy library installed. You can install it using pip:

  ```sh
  pip install scapy

## Example 


============================================================
Packet captured!
Source IP      : 192.168.1.10
Destination IP : 192.168.1.1
Protocol       : TCP
Payload        : b'E\x00\x00<\x1cF@\x00@\x06\xa6\xec\xc0\xa8\x01\n\xc0\xa8\x01\x01'
============================================================


============================================================
Packet captured!
Source IP      : 192.168.1.15
Destination IP : 8.8.8.8
Protocol       : UDP
Payload        : b'\x00\x01\x00\x00\x00\x00\x00\x00'
============================================================
