# 🛡️ CyberSec-Scripts

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/willedwardsjr/CyberSec-Scripts/graphs/commit-activity)

A curated collection of custom Python and Bash scripts designed for threat hunting, log analysis, automation, and defensive security operations (Blue Team). Developed as part of a Tier 2 SOC Analyst portfolio.

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
- **`Automated_Threat_Hunter.py`**: Ingests raw text and JSON logs, using regex signatures to detect indicators of compromise (IoCs) and map them directly to the MITRE ATT&CK framework.
- **`evtx_parser.py`**: Extracts and filters critical Windows Event Logs (e.g., Event ID 4624, 4688) for rapid triage during an incident response engagement.
- **`wazuh_react_agent.py`**: A security-focused AI agent utilizing a pure Python ReAct loop configured to query the Wazuh API for automated incident triage.

### 2. Network Security
- **`port_scanner_banner.py`**: A lightweight, multi-threaded TCP port scanner that attempts banner grabbing to identify running services and versions.
- **`pcap_extractor.py`**: Parses `.pcap` files to extract HTTP requests, DNS queries, and cleartext credentials from network traffic.
- - How it Works
  - -- Memory Efficiency: Rather than loading the entire .pcap file into RAM using scapy.rdpcap(), the script uses scapy.sniff(offline=..., store=0). This processes the file
  - --packet-by-packet, allowing you to parse multi-gigabyte captures without crashing your machine.
  - --Targeted Extraction:
  - - --HTTP/DNS: Uses Scapy's built-in HTTPRequest and DNSQR layers to cleanly strip the method, URL, and queried domains without wrestling with raw byte offsets.
    - --Credentials: Since cleartext protocols (FTP, Telnet, HTTP) embed credentials in the raw TCP data layer, the script decodes the scapy.packet.Raw payload and applies highly
    - --specific Regex patterns to catch USER/PASS commands, URL-encoded POST forms, and base64-encoded basic authentication headers. It automatically decodes the base64 headers for
    - --you.
### 3. Automation & OSINT
- **`ip_rep_checker.py`**: Automates querying IPs against VirusTotal and AbuseIPDB APIs to determine their reputation score.
- How It Works
- --Dual Intelligence:
- --It queries AbuseIPDB for historical reporting, brute-force behavior, and usage context (e.g., Data Center vs. Residential). It simultaneously queries VirusTotal
- --for malware association and engine detections.
- --Rate Limit Management:
- --The standard free tier for VirusTotal restricts users to 4 requests per minute. When passing a file of IPs via the -f flag, the script automatically
- --implements a 16-second sleep (-d 16) between iterations to prevent your account from being temporarily banned for hitting the HTTP 429 Too Many Requests threshold.
- --Safe API Handling:
- --Extracts metrics natively from the JSON responses and implements standard fallback/error handling in case an API endpoint drops the connection or returns an unexpected schema.


- **`subdomain_enum.sh`**: A Bash wrapper that chains together multiple OSINT tools (like `Sublist3r` and `Amass`) to discover subdomains for a target scope.
- --How It Works:
- --Tool Chain Addition: Alongside your requested Amass and Sublist3r, I injected Subfinder. Sublist3r is historically great but relies on older scrapers; Subfinder is a modern, highly - --maintained Go-based tool that significantly increases the fidelity of bug bounty and OSINT hunts.
- --Passive Safety: Amass is executed with the -passive flag. This ensures it only scrapes external OSINT sources (like passive DNS, Certificate Transparency logs, and search engines) - --rather than actively throwing DNS queries or brute-forcing the target, which maintains OPSEC and prevents tipping off defense teams early in the recon phase.
- --Data Normalization: The script takes the output text files from all three tools, strips out wildcard asterisks (*.), converts everything to lowercase, and uses sort -u to
- --mathematically deduplicate the list into a single, clean final_subdomains.txt file ready to be piped into tools like httpx or nmap.
  

---

## ⚙️ Prerequisites

Most scripts are written in Python 3. Ensure you have the following installed:
- Python 3.8 or higher
- `pip` (Python package installer)
- Windows, macOS or Unix/Linux environment

---

## 🚀 Installation

1. Clone the repository to your local machine:
   ```bash
   git clone [https://github.com/cyberguywill/CyberSec-Scripts.git](https://github.com/willedwardsjr/CyberSec-Scripts.git)
