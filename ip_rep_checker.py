# Install Dependencies: The script utilizes the standard requests library. 
### Bash pip install requests
# Configure API Keys: You must export your API keys as environment variables. This prevents hardcoding credentials into your scripts, which is a major security risk.
### Bash export VT_API_KEY="your_virustotal_api_key"
### export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
# Check a Single IP
### Bash python ip_rep_checker.py -i 8.8.8.8
# Check a list of IPs (Bulk Triage): Create a tetxt file (ips.txt) with one IP per line
### Bash python ip_rep_checker.py -f ips.txt
import argparse
import os
import sys
import time
import requests

# API Endpoints
VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

def get_api_keys():
    """Retrieves API keys from environment variables."""
    vt_key = os.getenv("VT_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    
    if not vt_key or not abuse_key:
        print("[-] Error: Missing API keys.")
        print("[*] Please set them using:")
        print("    export VT_API_KEY='your_virustotal_key'")
        print("    export ABUSEIPDB_API_KEY='your_abuseipdb_key'")
        sys.exit(1)
        
    return vt_key, abuse_key

def check_virustotal(ip, api_key):
    """Queries VirusTotal API v3 for IP reputation."""
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(f"{VT_API_URL}{ip}", headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            owner = data.get("as_owner", "Unknown")
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            
            return {
                "owner": owner,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "total_engines": sum(stats.values())
            }
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded (VT)."}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_abuseipdb(ip, api_key):
    """Queries AbuseIPDB for IP reputation."""
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(ABUSEIPDB_API_URL, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"),
                "usage_type": data.get("usageType", "Unknown"),
                "domain": data.get("domain", "Unknown")
            }
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded (AbuseIPDB)."}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def print_report(ip, vt_data, abuse_data):
    """Formats and prints the results to the terminal."""
    print(f"\n{'='*50}")
    print(f" REPORT FOR IP: {ip}")
    print(f"{'='*50}")

    # AbuseIPDB Section
    print("[ AbuseIPDB ]")
    if "error" in abuse_data:
        print(f"  [-] Error: {abuse_data['error']}")
    else:
        score = abuse_data['confidence_score']
        # Flag as critical if confidence score is > 50
        score_display = f"{score}%" + (" (HIGH RISK!)" if score > 50 else "")
        print(f"  Confidence Score : {score_display}")
        print(f"  Total Reports    : {abuse_data['total_reports']}")
        print(f"  Country          : {abuse_data['country']}")
        print(f"  Usage Type       : {abuse_data['usage_type']}")
        print(f"  Domain           : {abuse_data['domain']}")

    print("-" * 50)

    # VirusTotal Section
    print("[ VirusTotal ]")
    if "error" in vt_data:
        print(f"  [-] Error: {vt_data['error']}")
    else:
        malicious = vt_data['malicious']
        # Flag as critical if any engine marks as malicious
        mal_display = str(malicious) + (" (MALICIOUS!)" if malicious > 0 else "")
        print(f"  Malicious Hits   : {mal_display} / {vt_data['total_engines']}")
        print(f"  Suspicious Hits  : {vt_data['suspicious']}")
        print(f"  AS Owner         : {vt_data['owner']}")
        
    print(f"{'='*50}\n")

def process_ip(ip, vt_key, abuse_key):
    """Orchestrates the checks for a single IP."""
    print(f"[*] Querying databases for {ip}...")
    vt_result = check_virustotal(ip, vt_key)
    abuse_result = check_abuseipdb(ip, abuse_key)
    print_report(ip, vt_result, abuse_result)

def main():
    parser = argparse.ArgumentParser(description="Automated IP Reputation Checker using VirusTotal & AbuseIPDB")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", help="Single IP address to check")
    group.add_argument("-f", "--file", help="Text file containing a list of IP addresses (one per line)")
    parser.add_argument("-d", "--delay", type=int, default=16, help="Delay between checks for files in seconds to avoid VT free rate limits (Default: 16)")
    
    args = parser.parse_args()
    vt_key, abuse_key = get_api_keys()

    if args.ip:
        process_ip(args.ip.strip(), vt_key, abuse_key)
    
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            print(f"[*] Loaded {len(ips)} IPs from {args.file}")
            for index, ip in enumerate(ips):
                process_ip(ip, vt_key, abuse_key)
                # Respect rate limits on all but the last IP
                if index < len(ips) - 1:
                    print(f"[*] Sleeping for {args.delay} seconds to respect API rate limits...")
                    time.sleep(args.delay)
                    
        except FileNotFoundError:
            print(f"[-] Error: File '{args.file}' not found.")
            sys.exit(1)

if __name__ == "__main__":
    main()
