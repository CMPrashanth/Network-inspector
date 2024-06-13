# Network Packet Analyzer

## Overview

Network Packet Analyzer is a Python-based GUI application designed to sniff and analyze network packets in real-time. It captures packets, extracts essential information such as source and destination addresses, protocol types, and payload, and displays them in a user-friendly interface.

## Features

- Real-time packet sniffing
- Display of source and destination addresses, protocol types, and payloads
- Hexdump format for payload display
- Double-click on a packet to view the full payload
- Start and stop packet sniffing

## Prerequisites

- Python 3.x
- Scapy
- Tkinter (comes pre-installed with Python)
- Threading (comes pre-installed with Python)

## Usage

1. Run the application:
    ```bash
    python packet_sniffer.py
    ```

2. Use the GUI to start and stop packet sniffing:
    - Click "Start Sniffing" to begin capturing packets.
    - Click "Stop Sniffing" to stop capturing packets.
    - Double-click on any packet in the list to view its full payload in a new window.
