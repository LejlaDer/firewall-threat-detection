# Firewall Threat Detection

A real-time firewall log analysis and threat detection system for Debian-based Linux systems.

## Project Status

🚧 **In progress** — university thesis project.

This project focuses on building a lightweight threat detection tool that monitors UFW firewall logs in real time, checks suspicious IP addresses against the FireHOL blacklist, applies a machine learning model for threat scoring, and stores detected threats in a local SQLite database. [file:1]

## Overview

The goal of this project is to provide a simple Linux-based monitoring tool that can be installed and run with minimal configuration. The system is designed for Debian-based environments and currently supports real-time UFW log parsing, blacklist checking, ML-based threat scoring, WHOIS enrichment, SQLite storage, and basic CLI inspection. 

## Implemented Features

- Real-time UFW log monitoring 
- FireHOL blacklist matching with subnet support 
- Random Forest machine learning model for port-based threat scoring 
- Combined threat score based on blacklist and ML results 
- WHOIS lookup for suspicious public IP addresses 
- SQLite database storage for detected threats
- Test mode using `sample_ufw.log` 
- Basic CLI commands for threat listing and status checking

## Planned Features

- Email notifications on threat detection 
- Extended CLI interface (`fwmonitor status`, `fwmonitor threats`, `fwmonitor report <ip>`
- `.deb` packaging for easier installation 
- Optional local web dashboard 

## Requirements

- Ubuntu 24.04 or another Debian-based Linux distribution 
- Python 3.12 
- UFW enabled with logging turned on 

## Setup

```bash
# Clone the repository
git clone https://github.com/LejlaDer/firewall-threat-detection.git
cd firewall-threat-detection

# Create and activate virtual environment
python3 -m venv ~/fwmonitor-env
source ~/fwmonitor-env/bin/activate

# Install dependencies
pip install requests ipwhois scikit-learn pandas joblib

# Enable UFW and logging
sudo ufw enable
sudo ufw logging on
```

## Usage

### Train the model

```bash
python3 src/train_model.py
```

### Run test mode

```bash
python3 src/monitor.py --test
```

### Show detected threats

```bash
python3 src/monitor.py --threats 10
```

### Show total threat count

```bash
python3 src/monitor.py --status
```

### Run real-time monitoring

```bash
python3 src/monitor.py
```

## Project Structure

```bash
firewall-threat-detection/
├── src/
│   ├── monitor.py
│   └── train_model.py
├── model/
│   └── model.pkl
├── data/
│   └── firewall_data.csv
├── sample_ufw.log
├── threats.db
└── README.md
```

## Notes

This repository is currently under active development as part of a university thesis project. The implementation is still being extended and some planned features are not yet finished.