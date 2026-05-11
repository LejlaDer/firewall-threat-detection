# Firewall Threat Detection

A real-time firewall log analysis and threat detection system for Debian-based Linux systems.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Platform: Debian/Ubuntu](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu-orange.svg)](https://ubuntu.com/)

## Overview

This tool continuously monitors UFW firewall logs in real time, checks suspicious IP addresses against the FireHOL IP blacklist, and applies a Random Forest machine learning model to assign a threat score to each suspicious event. When a threat is confirmed, the system performs a WHOIS lookup, stores the record in a local SQLite database, and sends an email alert to the configured recipient.

The system is designed to be lightweight and easy to deploy on any Debian-based Linux machine — from a personal workstation to a cloud VPS — without requiring dedicated security infrastructure.

## Features

- Real-time UFW log monitoring via file tailing
- FireHOL blacklist matching with subnet-aware IP lookup (4,587+ networks)
- Random Forest ML model for traffic-based threat scoring
- Combined threat score from blacklist status and ML probability
- WHOIS enrichment (country, ISP) for confirmed threats
- SQLite database storage with deduplication
- Email alerts via SMTP on new threat detection
- CLI interface for status and threat listing
- Test mode using a prepared sample log file
- Debian `.deb` package available via PPA

## Installation

### Option A — APT (recommended)

```bash
sudo add-apt-repository ppa:lejladervisevic/firewall-threat-detection
sudo apt update
sudo apt install firewall-threat-detection
```

### Option B — Manual (from source)

```bash
git clone https://github.com/LejlaDer/firewall-threat-detection.git
cd firewall-threat-detection

python3 -m venv ~/fwmonitor-env
source ~/fwmonitor-env/bin/activate

pip install requests ipwhois scikit-learn pandas joblib

sudo ufw enable
sudo ufw logging on
```

Copy `.env.example` to `.env` and fill in your SMTP credentials and recipient email.

## Updating

### Option A — APT
sudo apt update && sudo apt upgrade firewall-threat-detection

### Option B — Manual
cd firewall-threat-detection
git pull
pip install -r requirements.txt

## Usage

```bash
# Activate environment (manual install only)
source ~/fwmonitor-env/bin/activate

# Show help and all available options
python3 src/monitor.py --help

# Run in test mode (uses data/sample_ufw.log)
python3 src/monitor.py --test

# Start real-time monitoring
python3 src/monitor.py

# Show last N detected threats
python3 src/monitor.py --threats 10

# Show system status and threat count
python3 src/monitor.py --status
```

### CLI Reference

| Command                            | Description                                              |
|------------------------------------|----------------------------------------------------------|
| `--help`                           | Show all available commands and usage information        |
| `--test`                           | Run in test mode using `data/sample_ufw.log`             |
| `--threats N`                      | Display the last N detected threats from the database    |
| `--status`                         | Show total number of threats detected                    |
| *(no arguments)*                   | Start real-time monitoring of `/var/log/ufw.log`         |

## Project Structure

```
firewall-threat-detection/
├── src/
│   ├── monitor.py          # Main entry point, CLI handler
│   ├── detector_poc.py     # Detection logic
│   └── train_model.py      # ML model training script
├── model/
│   └── rf_model.joblib     # Trained Random Forest model
├── data/
│   └── sample_ufw.log      # Sample log for --test mode
├── debian/                 # Debian packaging files
├── .env                    # SMTP credentials (not committed)
├── firehol_level1.txt      # FireHOL IP blacklist
├── config.example.json     # Example configuration
└── README.md
```

## Requirements

- Ubuntu 24.04 or any Debian-based Linux distribution
- Python 3.10+
- UFW enabled with logging turned on (`sudo ufw logging on`)
- SMTP account for email alerts (e.g. Gmail with App Password)

## ML Model

The threat scoring model is a Random Forest classifier trained on the [UCI Firewall Logs dataset](https://archive.ics.uci.edu/dataset/542/internet+firewall+data) (65,532 samples). It achieved **99.95% accuracy**, **99.93% precision**, and **99.96% recall** on the held-out test set. The model is loaded at startup and never retrained during normal operation.

## Author

Lejla Dervišević — undergraduate thesis project, International Burch University, 2025/2026
