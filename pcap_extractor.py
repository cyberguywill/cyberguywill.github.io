# Install Scapy: This script depends on scapy, a powerful manipultation tool for Python
### Bash pip install scapy
# Run the analyzer: Provide the path to your packet capture file. It supports standard .pcap and modern .pcapng formats
### python pcap_extractor.py capture.pcapng
# Capture live traffic for testing (optional): If you need a test file, use tcpdump on a linux machine to generate a small PCAP to parse
### Bash sudo tcpdump -i eth0 -w test.pcap -c 1000
import argparse
import re
import sys
import base64

try:
    import scapy.all as scapy
    from scapy.layers.inet import TCP, UDP
    from scapy.layers.dns import DNSQR
    from scapy.layers.http import HTTPRequest
    from scapy.packet import Raw
except ImportError:
    print("[-] Missing required library. Please install it using: pip install scapy")
    sys.exit(1)

def extract_dns(packet):
    """Extracts requested domains from DNS queries."""
    if packet.haslayer(DNSQR):
        try:
            qname = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            print(f"[DNS] Query: {qname}")
        except Exception:
            pass

def extract_http(packet):
    """Extracts HTTP methods, hosts, and paths."""
    if packet.haslayer(HTTPRequest):
        try:
            host = packet[HTTPRequest].Host.decode('utf-8', errors='ignore') if packet[HTTPRequest].Host else ""
            path = packet[HTTPRequest].Path.decode('utf-8', errors='ignore') if packet[HTTPRequest].Path else ""
            method = packet[HTTPRequest].Method.decode('utf-8', errors='ignore') if packet[HTTPRequest].Method else ""
            
            # Reconstruct the full URL for the terminal
            url = f"{host}{path}"
            print(f"[HTTP] {method} {url}")
        except Exception:
            pass

def extract_credentials(packet):
    """Hunts for cleartext passwords in FTP, Telnet, HTTP Basic Auth, and POST bodies."""
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # 1. FTP Credentials
            if re.search(r"^(USER|PASS)\s+", payload, re.IGNORECASE):
                lines = payload.strip().split('\n')
                for line in lines:
                    if line.upper().startswith("USER ") or line.upper().startswith("PASS "):
                        print(f"[CREDS] FTP: {line.strip()}")

            # 2. HTTP Basic Authentication
            basic_auth_match = re.search(r"Authorization:\sBasic\s([A-Za-z0-9+/=]+)", payload)
            if basic_auth_match:
                b64_string = basic_auth_match.group(1)
                try:
                    decoded = base64.b64decode(b64_string).decode('utf-8')
                    print(f"[CREDS] HTTP Basic Auth: {decoded}")
                except Exception:
                    print(f"[CREDS] HTTP Basic Auth (Base64): {b64_string}")

            # 3. URL-Encoded Form Data (e.g., POST requests)
            # Looks for common username/password parameter names in the payload body
            cred_patterns = [
                r"(?i)(user(?:name)?=[^&\s]+&pass(?:word)?=[^&\s]+)",
                r"(?i)(email=[^&\s]+&password=[^&\s]+)",
                r"(?i)(log(?:in)?=[^&\s]+&pwd=[^&\s]+)"
            ]
            for pattern in cred_patterns:
                form_match = re.search(pattern, payload)
                if form_match:
                    print(f"[CREDS] Form Data: {form_match.group(1)}")

            # 4. Telnet or generic raw logins (heuristic based on common prompts)
            # This is noisy, so we scope it tightly to "login:" or "password:" followed by input
            if re.search(r"(?i)(login|user|password):\s*\w+", payload):
                lines = payload.strip().split('\n')
                for line in lines:
                    if re.search(r"(?i)(login|user|password):\s*\w+", line):
                        print(f"[CREDS] Generic/Telnet: {line.strip()}")

        except Exception:
            pass

def process_packet(packet):
    """Routing function to pass the packet through all extractors."""
    extract_dns(packet)
    extract_http(packet)
    extract_credentials(packet)

def main():
    parser = argparse.ArgumentParser(description="PCAP Extractor: Hunts for DNS, HTTP, and Cleartext Credentials")
    parser.add_argument("pcap_file", help="Path to the .pcap or .pcapng file")
    args = parser.parse_args()

    # Load the HTTP layer explicitly since it's an extension in Scapy
    scapy.load_layer("http")

    print(f"[*] Analyzing PCAP: {args.pcap_file}")
    print("[*] Extracting DNS, HTTP requests, and cleartext credentials...\n")
    print("-" * 70)

    try:
        # sniff(offline=...) is highly memory efficient compared to rdpcap() for large files
        # store=0 ensures packets are discarded from memory after process_packet runs
        scapy.sniff(offline=args.pcap_file
