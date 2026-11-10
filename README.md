# 🛡️ CyberSec-Scripts

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yourusername/CyberSec-Scripts/graphs/commit-activity)

A curated collection of custom Python and Bash scripts designed for threat hunting, log analysis, automation, and defensive security operations (Blue Team). 

> **⚠️ Legal Disclaimer:** 
> The scripts and tools provided in this repository are for **educational purposes and authorized security testing only**. Do not use these tools on systems or networks you do not own or do not have explicit permission to test. The author is not responsible for any misuse or damage caused by these scripts.

---

## 📑 Table of Contents
- [Script Inventory](#-script-inventory)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage Examples](#-usage-examples)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🛠️ Script Inventory

### 1. Threat Hunting & Log Analysis
* **`mitre_log_analyzer.py`**: Ingests raw text and JSON logs, using regex signatures to detect indicators of compromise (IoCs) and map them directly to the MITRE ATT&CK framework.
* **`evtx_parser.py`**: Extracts and filters critical Windows Event Logs (e.g., Event ID 4624, 4688) for rapid triage during an incident response engagement.

### 2. Network Security
* **`port_scanner_banner.py`**: A lightweight, multi-threaded TCP port scanner that attempts banner grabbing to identify running services and versions.
* **`pcap_extractor.py`**: Parses `.pcap` files to extract HTTP requests, DNS queries, and cleartext credentials from network traffic.

### 3. Automation & OSINT
* **`ip_rep_checker.py`**: Automates querying IPs against VirusTotal and AbuseIPDB APIs to determine their reputation score.
* **`subdomain_enum.sh`**: A Bash wrapper that chains together multiple OSINT tools (like `Sublist3r` and `Amass`) to discover subdomains for a target scope.

---

## ⚙️ Prerequisites

Most scripts are written in Python 3. Ensure you have the following installed:
- Python 3.8 or higher
- `pip` (Python package installer)
- Unix/Linux environment (recommended for bash scripts)

---

## 🚀 Installation

1. Clone the repository to your local machine:
   ```bash
   git clone [https://github.com/yourusername/CyberSec-Scripts.git](https://github.com/yourusername/CyberSec-Scripts.git)
