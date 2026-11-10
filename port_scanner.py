#Scan a target using defaults (Ports 1-1024, 100 threads)
##python port_scanner.py 192.168.1.10
#Scan the full port range using 500 threads with a faster 0.5s timeout
##python port_scanner.py scanme.nmap.org -s 1 -e 65535 -t 500 -w 0.5
import socket
import argparse
import concurrent.futures
import time

def grab_banner(s):
    """
    Attempts to grab a service banner from an open socket.
    Handles both immediately talkative services and those requiring a prompt.
    """
    try:
        # Increase timeout slightly to wait for services that send a banner upon connection (e.g., SSH, FTP)
        s.settimeout(1.5)
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        
        if not banner:
            # If no banner, send a basic HTTP HEAD request to coax a response from web servers
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            
        # Clean up the banner for single-line terminal display
        if banner:
            banner = banner.replace('\r', ' ').replace('\n', ' - ')
            return banner[:90] + '...' if len(banner) > 90 else banner
    except Exception:
        pass
    return ""

def scan_port(ip, port, timeout):
    """Checks if a port is open and triggers banner grabbing if successful."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            # connect_ex returns 0 on successful connection
            if s.connect_ex((ip, port)) == 0:
                banner = grab_banner(s)
                return port, True, banner
    except Exception:
        pass
    return port, False, ""

def main():
    parser = argparse.ArgumentParser(description="Lightweight Multi-threaded TCP Scanner with Banner Grabbing")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("-w", "--wait", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname {args.target}")
        return

    print(f"[*] Starting scan on {target_ip} ({args.target})")
    print(f"[*] Scanning ports {args.start} to {args.end} with {args.threads} threads...\n")

    start_time = time.time()
    open_ports = []

    # ThreadPoolExecutor handles the multi-threading context and queue
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit all ports to the executor
        futures = {
            executor.submit(scan_port, target_ip, port, args.wait): port 
            for port in range(args.start, args.end + 1)
        }
        
        # Process results as soon as each thread finishes
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append(port)
                if banner:
                    print(f"[+] Port {port:5}/tcp OPEN  | Banner: {banner}")
                else:
                    print(f"[+] Port {port:5}/tcp OPEN  | Banner: [No response]")

    print(f"\n[*] Scan completed in {time.time() - start_time:.2f} seconds.")
    print(f"[*] Found {len(open_ports)} open ports.")

if __name__ == "__main__":
    main()
