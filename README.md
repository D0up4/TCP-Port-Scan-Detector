# TCP Port Scan Detector

## Author
D0up4

## Last Updated
06/2025

---

## Description

This project is a lightweight TCP port scan detector built with Python and Scapy. It captures live TCP traffic on a network interface and analyzes SYN packets to identify potential port scanning or brute-force activity based on the frequency of connection attempts to different ports.

---

## Features

- Captures live TCP packets using Scapy
- Detects suspicious SYN packet bursts indicating possible port scans or brute-force attacks
- Configurable thresholds for detection sensitivity (number of attempts and time window)
- Simple console output alerts when suspicious activity is detected
- Pure Python implementation with minimal dependencies

---

## Usage

Run the script with administrative privileges to allow packet capturing:

```bash
sudo python port_scan_detector.py
