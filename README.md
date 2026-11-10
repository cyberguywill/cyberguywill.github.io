# 🛡️ CyberSec-Scripts

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/willedwardsjr/CyberSec-Scripts/graphs/commit-activity)

A curated collection of custom Python and Bash scripts designed for threat hunting, log analysis, automation, and defensive security operations (Blue Team). Developed as part of a Tier 2 SOC Analyst portfolio.

> **⚠️ Legal Disclaimer:** 
> The scripts and tools provided in this repository are for **educational purposes and authorized security testing only**. Do not use these tools on systems or networks you do not own or do not have explicit permission to test. The author is not responsible for any misuse or damage caused by these scripts.

---

## 📑 Table of Contents
- [Threat Hunting & Log Analysis](#1-threat-hunting--log-analysis)
- [Network Security](#2-network-security)
- [Automation & OSINT](#3-automation--osint)
- [Prerequisites](#%EF%B8%8F-prerequisites)
- [Installation](#-installation)
- [Usage Examples](#%EF%B8%8F-usage-examples)
- [Contributing](#-contributing)
- [License](#https://github.com/cyberguywill/cyberguywill.github.io/blob/cybersecurity/LICENSE)

---

## 🛠️ Script Inventory

### 1. Threat Hunting & Log Analysis
#### **`Automated_Threat_Hunter.py`**: Ingests raw text and JSON logs, using regex signatures to detect indicators of compromise (IoCs) and map them directly to the MITRE ATT&CK framework.
How to scale for production: If you plan to use this on real-world networks or large datasets, you can upgrade this foundational script in three ways

- **`evtx_parser.py`**: Extracts and filters critical Windows Event Logs (e.g., Event ID 4624, 4688) for rapid triage during an incident response engagement.
- -How it works:
- -Context-Aware Extraction:
  - - --Rather than just dumping raw XML/JSON to the terminal, the format_event_data function specifically targets the most vital EventData keys based on the Event ID.
    - --If it spots 4688, it extracts the CommandLine and NewProcessName; if it spots 4624, it grabs TargetUserName and IpAddress.
- --Resilent Parsing:
-  - --The Windows EVTX schema occassionally wraps attributes (like EventID) or TimeCreated) inside secondary dictionary structures depending on OS version and qualifiers.
   - --The extract_event_details function normalizes these structures so the script doesn't crash on anomalous log formats.
- **`wazuh_react_agent.py`**: A security-focused AI agent utilizing a pure Python ReAct loop configured to query the Wazuh API for automated incident triage.
- -- Archetecture Breakdown
- - --Wazuh API client (WazuhClient):
  - --Standard implementation of the Wazuh v4 API using standard requests. It handles the two-step authentication process (fetching a JWT token via basic auth, then passing it as
  - --a Bearer token) and contains the programmatic binding (get_agent_info, get_rule_details) that the LLM will call.
- -- ReAct Loop implemetation (SecurityReActAgent):
  - --A pure Python implementation of LangChain-style zero-shot ReAct agent. In enforces the Thought -> Action -> Observation pipeline using strict system prompts and regular
  - --expresions to parse the LLM's output.
- --The stop sequence hook:
- - --Notice "stop" ["Observation:"] in the LLM parameters. This forces the LLM to pause generation immediately after declaring the tool it wants to use. Control is yielded back
  - --to the Python script, which queries the actual Wazuh API, grabs the response, injects it back into the context as the "Observation,: and resumes the loop.
- --How to run locally with Ollama (air-gapped/on prem)
- - --Install Ollama and pull a capable model (e.g. ollama run llama3).
  - --Export your environment variables to point the script at your local instance:
  - - --Bash
    - --export OPENAI_BASE_URL="http://127.0.0.1:11434/v1"
    - --export OPENAI_API_KEY="ollama"
    - --export WAZUH_API_URL="https://your-wazuh-manager:55000"
    - --export WAZUH_USER="your_wazuh_api_user"
    - --export WAZUH_PASSWORD="your_wazah_api_password"
- --Run the script: python wazuh_react_agent.py


### 2. Network Security
- **`port_scanner.py`**: A lightweight, multi-threaded TCP port scanner that attempts banner grabbing to identify running services and versions.
- --How it works
- - --Concurrency: Utilizes Python's concurrent.futures.ThreadPoolExecutor. This avoids the overhead of manually manageing thread queues and allows you to easily throttle
  - --the aggression of the scan via the -t flag
  - --Dual-Phase Banner Grabbing:
  -  - --Passive Listen: The scanner first waits 1.5 seconds for talkative services (like SSH, FTP, SMTP) that automatically broadcast their software version upon connection.
     - --Active Probe: If nothing is received, it sends a generic HEAD / HTTP/1.0\r\n\r\n request. This forces quiet web servers (HTTP/HTTPS) or tother requests-response services
     - --to spit back a Server: header or error message identifying themselves.
  - --Clean Output: Banners are stripped of carriage returns, truncated to 90 characters, and flattened into a single line do the terminal output remains readable.
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

## 🛠️ Usage Examples
[Automated Threat Hunter](#1-threat-hunting--log-analysis)
- Use the Offical MITRE python library: Instead of hardcording descriptions and tactic names, you can intall mitreattack-python. This allows you to query the actual MITRE STIX database dynamically. If your script detects "T1059.00" you can use the library to pull down the latest mitigations, related threat actors, and descriptions straight from MITRE
- Support JSON logs: Security logs from SIEMs (like Splunsk or Elastic) or Windows Event Logs are usually exported as JSON. You can modify the analyze_logs function to use
- Python's json module, allowing you to search specific fields (like CommandLine or EventID) instead full text lines.
- External Rules: Move the DETECTION_RULES dictionary to an external YAML or JSON file so you can update your threat intelligence signatures without modifying the core Python codes.
## ⚙️ Prerequisites

Most scripts are written in Python 3. Ensure you have the following installed:
- Python 3.8 or higher
- `pip` (Python package installer)
- Windows, macOS or Unix/Linux environment

---

## 🚀 Installation

1. Clone the repository to your local machine:
   ```bash
   git clone (https://github.com/cyberguywill/CyberSec-Scripts.git)
