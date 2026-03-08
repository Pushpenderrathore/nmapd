PyScanner

PyScanner v9.0 — Advanced Python Network Scanner

PyScanner is a high-performance network reconnaissance and port scanning framework written in Python. It provides modern scanning capabilities similar to professional tools while remaining fully scriptable and extensible in Python.

The tool supports TCP connect scans, SYN scans, distributed scanning, IPv6 support, OS fingerprinting, banner grabbing, service detection, and intelligent target permutation.

Source file: 

Features
Core Scanning

TCP Connect Scan

SYN Scan (raw socket based)

Ping Sweep / Host Discovery

IPv4 and IPv6 scanning

CIDR network scanning

Custom port ranges

Performance & Architecture

Stateless scanning engine (ZMap/Masscan style)

Token-bucket rate limiter

Distributed scanning mode

Epoll/select packet receiver

Target permutation engine (IDS-evasion)

High-concurrency scanning with threading

Detection Capabilities

Service detection

Banner grabbing

HTTP header collection

WHOIS lookup

Reverse DNS lookup

OS Fingerprinting

Advanced OS detection using multiple signals:

TTL normalization

TCP window size

TCP options

ECN support

IP ID sequence patterns

ICMP behaviour

Supports fingerprinting for:

Linux

Windows

macOS

FreeBSD / OpenBSD

Cisco devices

Solaris

Embedded / IoT systems

Security-grade Features

Stateless SYN scanning

HMAC-validated responses

Spoof-resistant packet validation

SYN cookie-style probe verification

Advanced Networking

BPF packet filtering

libpcap packet capture

Raw socket packet crafting

Internet-scale scanning architecture

Installation
Requirements

Python 3.8+

Optional packages:

python-whois

Install dependencies:

pip install python-whois
Usage
Basic Port Scan
python pyscanner.py -t 192.168.1.1 -p 1-1024
SYN Scan
python pyscanner.py -t 192.168.1.1 -p 1-1024 --scan-type syn
Network Scan
python pyscanner.py -t 192.168.1.0/24 -p 1-1000
Ping Sweep
python pyscanner.py -t 192.168.1.0/24 --ping-scan
IPv6 Scan
python pyscanner.py -t 2001:db8::1 -p 80,443 --scan-type syn --ipv6
Resume Scan
python pyscanner.py -t 10.0.0.0/24 -p 1-1024 --checkpoint state.json
python pyscanner.py -t 10.0.0.0/24 --resume state.json
Distributed Scan
python pyscanner.py -t 192.168.1.0/24 --distributed --workers 4
Export Results
python pyscanner.py -t 192.168.1.1 -p 1-1024 -o report.xml
Example Output
Host: 192.168.1.1
Status: UP
Latency: 12.4 ms

PORT     STATE   SERVICE
22/tcp   open    ssh
80/tcp   open    http
443/tcp  open    https

OS Guess: Linux 5.x (confidence: high)
Architecture Overview

PyScanner is built with a modular architecture.

Main components:

Scanner Core
│
├── Target Permutation Engine
├── Stateless SYN Scanner
├── Packet Capture Engine (libpcap / raw socket)
├── OS Fingerprinting Engine
├── Service Detection Engine
└── Reporting System

This architecture allows easy extension with additional scanning modules and scripts.

Project Goals

PyScanner was created to explore modern network scanning techniques used by large-scale scanners like:

Nmap

ZMap

Masscan

The objective is to implement high-performance scanning algorithms entirely in Python while keeping the code understandable for researchers and students.

Disclaimer

This tool is intended only for educational purposes and authorized security testing.

Do not scan systems without explicit permission.

The author is not responsible for misuse of this software.

Author

Pushpender Singh Rathore
B.Tech CSE | Cybersecurity Enthusiast
Python & C Developer

License

MIT License
