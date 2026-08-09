#!/usr/bin/env python3
"""Advanced TCP port scanner with Smart Banner Grabbing.

Usage examples:
  python port_scanner.py scanme.nmap.org
  python port_scanner.py 192.168.1.1 --ports 20-1024
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 100

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 123, 139, 143, 194, 443, 445, 465, 587, 631, 993, 995, 3306, 3389, 5900, 8080]


def parse_ports(ports: str) -> List[int]:
    result = set()
    for part in ports.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, high = part.split("-", 1)
            low = int(low)
            high = int(high)
            if low > high:
                low, high = high, low
            result.update(range(low, high + 1))
        else:
            result.add(int(part))
    return sorted(port for port in result if 1 <= port <= 65535)


def scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool, str, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    banner = ""
    
    try:
        sock.connect((host, port))
        
        # --- SMART BANNER GRABBING ---
        data = ""
        try:
            # 1. Listen first (for services like SSH that introduce themselves)
            sock.settimeout(0.5) 
            data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except socket.timeout:
            # 2. If it times out, the service is waiting for US to speak.
            try:
                if port in [80, 443, 8080]:
                    # Speak proper HTTP to web servers
                    probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
                else:
                    # Generic poke for other services
                    probe = b"\r\n\r\n"
                
                sock.sendall(probe)
                data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except OSError:
                pass
        except OSError:
            pass
            
        if data:
            # Try to find a "Server:" line for web servers
            lines = data.split('\n')
            for line in lines:
                if line.lower().startswith("server:"):
                    banner = line.strip()[:60]
                    break
            # If no "Server:" line is found, just grab the first line
            if not banner:
                banner = lines[0].strip()[:60]
        # -----------------------------

        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"
            
        return port, True, service, banner
        
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False, "", ""
    finally:
        sock.close()


def resolve_host(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve host '{target}': {exc}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="TCP port scanner")
    parser.add_argument("target", help="Target host or IP address")
    parser.add_argument("--ports", default=",".join(str(p) for p in COMMON_PORTS),
                        help="Comma-separated ports or ranges to scan (default: common ports)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="Socket timeout in seconds")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help="Number of concurrent threads")
    args = parser.parse_args()

    try:
        target_ip = resolve_host(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    ports = parse_ports(args.ports)
    if not ports:
        parser.error("No valid ports to scan")

    print(f"Scanning {args.target} [{target_ip}] with {len(ports)} ports using {args.threads} threads...\n")

    open_ports = []
    
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_port, target_ip, port, args.timeout): port for port in ports}
            for future in as_completed(futures):
                port, is_open, service, banner = future.result()
                if is_open:
                    open_ports.append((port, service, banner))
                    banner_text = f" | Banner: {banner}" if banner else ""
                    print(f"Port {port}/tcp OPEN   service={service}{banner_text}")
                    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(1)

    if not open_ports:
        print("\nNo open ports found.")
    else:
        open_ports.sort()
        print("\nOpen ports summary:")
        print("-" * 75)
        for port, service, banner in open_ports:
            banner_text = f" | {banner}" if banner else ""
            print(f"  {port}/tcp open  (service: {service}){banner_text}")


if __name__ == "__main__":
    main()