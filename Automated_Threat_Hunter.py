import re
import os

# Define detection rules mapped to MITRE ATT&CK techniques
# Each rule contains a regex pattern to look for in the log, 
# and the associated MITRE ATT&CK Tactic/Technique details.
DETECTION_RULES = [
    {
        "name": "PowerShell Download Cradle",
        "pattern": r"(?i)(Invoke-WebRequest|Net\.WebClient|DownloadString|DownloadFile)",
        "tactic": "Execution (TA0002)",
        "technique": "Command and Scripting Interpreter: PowerShell (T1059.001)",
        "description": "Adversaries may use PowerShell to download payloads from the internet."
    },
    {
        "name": "Base64 Encoded PowerShell",
        "pattern": r"(?i)(powershell.*-enc|powershell.*-EncodedCommand)",
        "tactic": "Defense Evasion (TA0005)",
        "technique": "Obfuscated Files or Information (T1027)",
        "description": "Adversaries encode PowerShell commands in Base64 to bypass detection."
    },
    {
        "name": "Scheduled Task Creation",
        "pattern": r"(?i)(schtasks.*/create|Register-ScheduledTask)",
        "tactic": "Persistence (TA0003), Privilege Escalation (TA0004)",
        "technique": "Scheduled Task/Job: Scheduled Task (T1053.005)",
        "description": "Adversaries abuse the Task Scheduler for recurring execution of malicious code."
    },
    {
        "name": "Local Account Creation",
        "pattern": r"(?i)(net\s+user\s+.*\/add|New-LocalUser)",
        "tactic": "Persistence (TA0003)",
        "technique": "Create Account: Local Account (T1136.001)",
        "description": "Adversaries may create a local account to maintain access to systems."
    },
    {
        "name": "Clearing Event Logs",
        "pattern": r"(?i)(wevtutil\s+cl|Clear-EventLog)",
        "tactic": "Defense Evasion (TA0005)",
        "technique": "Indicator Removal: Clear Windows Event Logs (T1070.001)",
        "description": "Adversaries may clear Windows Event Logs to hide intrusion activity."
    }
]

def analyze_logs(file_path):
    """
    Parses a log file line by line and matches against predefined MITRE ATT&CK rules.
    """
    if not os.path.exists(file_path):
        print(f"Error: Could not find the file {file_path}")
        return []

    print(f"Analyzing log file: {file_path}...\n")
    findings = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line_number, line in enumerate(file, 1):
            # Check each rule against the current log line
            for rule in DETECTION_RULES:
                if re.search(rule['pattern'], line):
                    findings.append({
                        "line_number": line_number,
                        "matched_text": line.strip(),
                        "rule_name": rule['name'],
                        "tactic": rule['tactic'],
                        "technique": rule['technique'],
                        "description": rule['description']
                    })
                    
    return findings

def print_report(findings):
    """
    Formats and prints the detection findings to the console.
    """
    if not findings:
        print("No suspicious activity detected in the logs.")
        return
        
    print(f"⚠️ Found {len(findings)} suspicious log entries mapped to MITRE ATT&CK:\n")
    print("-" * 80)
    for finding in findings:
        print(f"Line Number : {finding['line_number']}")
        print(f"Log Entry   : {finding['matched_text']}")
        print(f"Detection   : {finding['rule_name']}")
        print(f"Tactic      : {finding['tactic']}")
        print(f"Technique   : {finding['technique']}")
        print(f"Description : {finding['description']}")
        print("-" * 80)

if __name__ == "__main__":
    # Create a dummy log file to test the script
    sample_log = "sample_security.log"
    with open(sample_log, "w") as f:
        f.write("08:00:01 User logged in successfully.\n")
        f.write("08:05:22 powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHc...\n")
        f.write("08:10:45 net user attacker P@ssw0rd123 /add\n")
        f.write("08:15:30 wevtutil cl System\n")
        
    # Run the analysis
    results = analyze_logs(sample_log)
    print_report(results)
    
    # Cleanup sample file
    if os.path.exists(sample_log):
        os.remove(sample_log)