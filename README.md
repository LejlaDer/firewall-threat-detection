# firewall-threat-detection

A real-time network threat detection system for Debian-based Linux systems.

## Overview

This project presents the design and implementation of a real-time network threat detection system, distributed as a native Linux `.deb` package. Once installed on a Debian-based machine, the system runs as a background service that continuously reads and parses UFW firewall logs.

Log entries are evaluated against the FireHOL IP blacklist, with suspicious IP addresses identified either by exceeding a user-defined appearance threshold or by matching a known malicious subnet. Detected threats are stored in a local SQLite database, and automated whois lookups provide additional context such as country of origin and ISP.

The end goal is a lightweight tool that any user can install with a single command and have running with minimal configuration.

## Features

- Real-time UFW log parsing
- FireHOL blacklist matching (subnet-aware)
- Whois lookup for suspicious IPs
- Local SQLite database for threat history
- Email alerts on threat detection
- Command-line interface

## Requirements

- Debian-based Linux system (Ubuntu 24.04 recommended)
- Python 3.12+
- UFW enabled and logging on

## Setup

### 1. Enable UFW logging
```bash
sudo ufw enable
sudo ufw logging on
```

### 2. Clone the repository
```bash
git clone https://github.com/LejlaDer/firewall-threat-detection.git
cd firewall-threat-detection
```

### 3. Create virtual environment and install dependencies
```bash
python3 -m venv ~/fwmonitor-env
source ~/fwmonitor-env/bin/activate
pip install requests ipwhois
```

### 4. Download FireHOL blacklist
```bash
wget -O firehol_level1.txt https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
```

### 5. Run
```bash
python3 detector.py
```

## Project Status

Currently in development as a university thesis project. This repository contains the initial proof of concept.
