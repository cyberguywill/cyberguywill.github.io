Python
import requests
import json
import sys

def check_ip_reputation(ip_address, api_key):
    """Queries the AbuseIPDB API for a specific IP address."""
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90',
        'verbose': True
    }
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status() 
        return response.json().get('data', {})
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Error querying AbuseIPDB: {e}")
        return None

def format_analyst_report(data):
    """Formats the raw JSON data into a clean text report."""
    if not data:
        return "No data returned or invalid IP."
        
    output = []
    output.append(f"==================================================")
    output.append(f" AbuseIPDB Report: {data.get('ipAddress')}")
    output.append(f"==================================================")
    output.append(f" Confidence Score : {data.get('abuseConfidenceScore')}%")
    output.append(f" Total Reports    : {data.get('totalReports')}")
    output.append(f" Country          : {data.get('countryName')} ({data.get('countryCode')})")
    output.append(f" ISP              : {data.get('isp')}")
    output.append(f" Domain           : {data.get('domain')}")
    output.append(f" Usage Type       : {data.get('usageType')}")
    output.append(f" Last Reported    : {data.get('lastReportedAt')}")
    
    if 'reports' in data and data['reports']:
        output.append("\n--- Recent Reports (Top 3) ---")
        for report in data['reports'][:3]:
            comment = report.get('comment', '').replace('\n', ' ').strip()
            if len(comment) > 80:
                comment = comment[:77] + "..."
            
            output.append(f"[*] {report.get('reportedAt')} | Categories: {report.get('categories')}")
            output.append(f"    Comment: {comment}\n")
            
    return "\n".join(output)

def post_to_slack(webhook_url, message):
    """Sends the formatted report to a Slack webhook."""
    headers = {'Content-Type': 'application/json'}
    
    # Wrap the message in Markdown code blocks for monospace formatting in Slack
    payload = {
        'text': f"```\n{message}\n```"
    }
    
    try:
        response = requests.post(webhook_url, headers=headers, json=payload)
        response.raise_for_status()
        print("[+] Successfully posted report to Slack.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error posting to Slack: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python abuseipdb_check.py <IP_ADDRESS>")
        sys.exit(1)
        
    ip_to_check = sys.argv[1]
    
    # --- INSERT YOUR CREDENTIALS HERE ---
    API_KEY = 'YOUR_API_KEY_HERE' 
    SLACK_WEBHOOK = 'YOUR_SLACK_WEBHOOK_URL_HERE'
    
    if API_KEY == 'YOUR_API_KEY_HERE':
        print("ERROR: Please insert your AbuseIPDB API key into the script.")
        sys.exit(1)
        
    print(f"[*] Querying AbuseIPDB for {ip_to_check}...\n")
    raw_data = check_ip_reputation(ip_to_check, API_KEY)
    
    if raw_data:
        report = format_analyst_report(raw_data)
        
        # Print to terminal for local viewing
        print(report)
        print("-" * 50)
        
        # Send to Slack if the webhook URL has been configured
        if SLACK_WEBHOOK != 'YOUR_SLACK_WEBHOOK_URL_HERE':
            print("[*] Sending report to Slack...")
            post_to_slack(SLACK_WEBHOOK, report)
        else:
            print("[!] Slack webhook URL not configured. Skipping Slack notification