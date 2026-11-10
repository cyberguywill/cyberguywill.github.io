import argparse
import json
import sys
from pathlib import Path

try:
    from evtx import Evtx
except ImportError:
    print("[-] Missing required library. Please install it using: pip install evtx")
    sys.exit(1)

def extract_event_details(record_json):
    """Safely extracts standard fields from the EVTX JSON structure."""
    event = record_json.get("Event", {})
    system = event.get("System", {})
    event_data = event.get("EventData", {})

    # Handle EventID (Can be an integer or a dict with qualifiers)
    raw_event_id = system.get("EventID")
    if isinstance(raw_event_id, dict):
        event_id = raw_event_id.get("#text", raw_event_id.get("text"))
    else:
        event_id = raw_event_id
    
    try:
        event_id = int(event_id)
    except (ValueError, TypeError):
        event_id = None

    # Handle Timestamp
    time_created = system.get("TimeCreated", {})
    if isinstance(time_created, dict):
        timestamp = time_created.get("#attributes", {}).get("SystemTime", "UNKNOWN_TIME")
    else:
        timestamp = time_created

    computer = system.get("Computer", "UNKNOWN_COMPUTER")

    return event_id, timestamp, computer, event_data

def format_event_data(event_id, event_data):
    """Extracts key fields based on specific IR triage Event IDs."""
    if not isinstance(event_data, dict):
        return str(event_data)

    if event_id in (4624, 4625):  # Logon / Failed Logon
        user = event_data.get("TargetUserName", "N/A")
        logon_type = event_data.get("LogonType", "N/A")
        ip = event_data.get("IpAddress", "N/A")
        return f"User: {user} | LogonType: {logon_type} | IP: {ip}"
    
    elif event_id == 4688:  # Process Creation
        process = event_data.get("NewProcessName", "N/A")
        cmdline = event_data.get("CommandLine", "N/A")
        return f"Process: {process} | CmdLine: {cmdline}"
    
    elif event_id == 7045:  # Service Installed
        service = event_data.get("ServiceName", "N/A")
        image = event_data.get("ImagePath", "N/A")
        return f"Service: {service} | Image: {image}"
    
    elif event_id == 1102:  # Audit Log Cleared
        return "AUDIT LOG CLEARED"

    # Default fallback for unmapped Event IDs
    # Truncate to 100 chars for terminal readability
    raw_data = json.dumps(event_data)
    return raw_data if len(raw_data) < 100 else raw_data[:97] + "..."

def main():
    parser = argparse.ArgumentParser(description="EVTX Parser for Rapid Incident Response Triage")
    parser.add_argument("evtx_file", help="Path to the .evtx file")
    parser.add_argument(
        "-i", "--ids", 
        type=int, 
        nargs="+", 
        default=[4624, 4625, 4688, 4720, 7045, 1102],
        help="Space-separated Event IDs to filter (Default: 4624 4625 4688 4720 7045 1102)"
    )
    parser.add_argument(
        "-o", "--output", 
        help="Optional: Output file to save raw filtered JSON lines"
    )
    args = parser.parse_args()

    evtx_path = Path(args.evtx_file)
    if not evtx_path.is_file():
        print(f"[-] Error: File '{args.evtx_file}' not found.")
        sys.exit(1)

    print(f"[*] Parsing: {evtx_path.name}")
    print(f"[*] Filtering for Event IDs: {args.ids}")
    print("-" * 110)
    print(f"{'TIMESTAMP':<30} | {'ID':<5} | {'COMPUTER':<20} | {'DETAILS'}")
    print("-" * 110)

    match_count = 0
    output_file = open(args.output, "w") if args.output else None

    try:
        # Initialize the Rust-based parser
        with Evtx(str(evtx_path)) as parser:
            for record in parser.records():
                try:
                    record_json = json.loads(record.data())
                    event_id, timestamp, computer, event_data = extract_event_details(record_json)

                    if event_id in args.ids:
                        match_count += 1
                        summary = format_event_data(event_id, event_data)
                        
                        # Print formatted line to console
                        print(f"{timestamp:<30} | {event_id:<5} | {computer:<20} | {summary}")

                        # Save full JSON line to file if requested
                        if output_file:
                            output_file.write(json.dumps(record_json) + "\n")

                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[-] Error reading EVTX file: {e}")
    finally:
        if output_file:
            output_file.close()

    print("-" * 110)
    print(f"[*] Triage complete. Found {match_count} matching events.")
    if args.output:
        print(f"[*] Full raw JSON records saved to {args.output}")

if __name__ == "__main__":
    main()