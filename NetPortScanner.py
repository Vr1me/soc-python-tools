import socket
import time
import argparse
import json
import csv
import os
import ipaddress
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

# Initialize colorama for Windows support
init(autoreset=True)

# Known services by port number (used as fallback if no banner received)
KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    902: "VMware", 912: "VMware",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP VPN",
    3306: "MySQL", 3389: "RDP", 3479: "PlayStation",
    4070: "Spotify", 4380: "Steam",
    5040: "Windows DAX API", 5222: "XMPP",
    5227: "Google Play", 5228: "Google Play",
    5238: "Google Play", 5261: "Google Play",
    5262: "Google Play", 5276: "Google Play",
    5278: "Google Play", 5287: "Google Play",
    5288: "Google Play", 5432: "PostgreSQL",
    5939: "VNC", 5353: "mDNS",
    6379: "Redis", 6463: "Discord",
    7680: "Windows Update P2P", 8000: "HTTP-Alt",
    8065: "Mattermost", 8080: "HTTP-Alt",
    8089: "Splunk", 8191: "League of Legends",
    8194: "Bloomberg", 9010: "Spiketrap",
    9180: "HTTP-Alt", 9200: "Elasticsearch",
    27015: "Steam Game", 27017: "MongoDB",
    27036: "Steam Remote Play", 27060: "Steam",
    45654: "Samsung Smart TV",
    49152: "Windows RPC", 49153: "Windows RPC",
    49154: "Windows RPC", 49155: "Windows RPC",
    49664: "Windows RPC", 49665: "Windows RPC",
    49666: "Windows RPC", 49667: "Windows RPC",
    49668: "Windows RPC", 49683: "Windows RPC",
    54908: "Corsair iCUE", 54909: "Corsair iCUE",
    63499: "Windows dynamic", 64203: "Windows dynamic",
}

# Common UDP services
UDP_SERVICES = {
    53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 123: "NTP", 137: "NetBIOS",
    138: "NetBIOS", 161: "SNMP", 162: "SNMP",
    500: "IKE VPN", 514: "Syslog", 520: "RIP",
    1194: "OpenVPN", 1900: "UPnP", 4500: "IPSec",
    5353: "mDNS", 5355: "LLMNR",
}


def parse_ports(ports_arg: str) -> list:
    # Parse port argument: "80,443,22" or "1-1024" or "22,80,100-200"
    ports = []
    for part in ports_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def grab_banner(sock: socket.socket) -> str:
    # Read what the server sends immediately after connection
    try:
        sock.settimeout(2.0)
        banner = sock.recv(1024)
        return banner.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def http_banner(host: str, port: int) -> str:
    # HTTP does not identify itself — send HEAD request to get server info
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((host, port))
        request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"
        sock.send(request.encode())
        response = sock.recv(1024).decode("utf-8", errors="ignore")
        sock.close()
        # Look for the Server header line
        for line in response.splitlines():
            if line.lower().startswith("server:"):
                return line.strip()
        return response.splitlines()[0] if response else ""
    except Exception:
        return ""


def get_service(port: int, banner: str, udp: bool = False) -> str:
    # Try to identify service by banner first, then fall back to known ports
    if banner:
        return banner.splitlines()[0][:50]
    if udp:
        return UDP_SERVICES.get(port, "unknown")
    return KNOWN_SERVICES.get(port, "unknown")


# --- TCP Connect scan --------------------------------------------------------

def scan_tcp_port(host: str, port: int, timeout: float = 0.5) -> dict:
    # Standard TCP connect scan
    result = {"port": port, "status": None, "service": "", "mode": "TCP"}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((host, port))

        if code == 0:
            result["status"] = "OPEN"
            banner = grab_banner(sock)
            sock.close()
            if not banner and port in (80, 8080, 8443, 8888):
                banner = http_banner(host, port)
            result["service"] = get_service(port, banner)
        else:
            result["status"] = "CLOSED"
            sock.close()

    except socket.timeout:
        result["status"] = "FILTERED"
    except (socket.gaierror, OSError):
        result["status"] = "ERROR"

    return result


# --- SYN scan (requires admin + npcap) --------------------------------------

def scan_syn_port(host: str, port: int, timeout: float = 1.0) -> dict:
    # SYN scan — sends only SYN, does not complete handshake
    result = {"port": port, "status": None, "service": "", "mode": "SYN"}
    try:
        import sys
        import os
        from scapy.all import IP, TCP, sr1, conf, send

        conf.verb = 0

        # Suppress scapy threading errors on Windows
        devnull = open(os.devnull, "w")
        old_stderr = sys.stderr
        sys.stderr = devnull

        try:
            pkt = IP(dst=host) / TCP(dport=port, flags="S")
            response = sr1(pkt, timeout=timeout, verbose=0)
        finally:
            sys.stderr = old_stderr
            devnull.close()

        if response is None:
            result["status"] = "FILTERED"
        elif response.haslayer(TCP):
            tcp_flags = response[TCP].flags
            if tcp_flags == 0x12:  # SYN-ACK — port is open
                result["status"] = "OPEN"
                result["service"] = get_service(port, "")
                send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)
            elif tcp_flags == 0x14:  # RST-ACK — port is closed
                result["status"] = "CLOSED"
        else:
            result["status"] = "FILTERED"

    except Exception:
        result["status"] = "ERROR"

    return result


# --- UDP scan (requires admin + npcap) ---------------------------------------

def scan_udp_port(host: str, port: int, timeout: float = 2.0) -> dict:
    # UDP scan — only report ports we know about or that send a response
    result = {"port": port, "status": None, "service": "", "mode": "UDP"}
    try:
        from scapy.all import IP, UDP, ICMP, sr1, conf
        conf.verb = 0

        pkt = IP(dst=host) / UDP(dport=port)
        response = sr1(pkt, timeout=timeout, verbose=0)

        if response is None:
            # No response — only report if it's a known UDP service
            if port in UDP_SERVICES:
                result["status"] = "OPEN|FILTERED"
                result["service"] = UDP_SERVICES[port]
            else:
                result["status"] = "CLOSED"
        elif response.haslayer(ICMP):
            icmp_type = response[ICMP].type
            icmp_code = response[ICMP].code
            if icmp_type == 3 and icmp_code == 3:  # port unreachable
                result["status"] = "CLOSED"
            else:
                result["status"] = "FILTERED"
        elif response.haslayer(UDP):
            # Got UDP response — port is definitely open
            result["status"] = "OPEN"
            result["service"] = get_service(port, "", udp=True)

    except Exception as e:
        result["status"] = "ERROR"
        result["service"] = str(e)[:30]

    return result


# --- Host scanner ------------------------------------------------------------

def scan_host(host: str, ports: list, timeout: float = 0.5,
              threads: int = 200, mode: str = "tcp") -> list:
    # Scan all ports on a single host using selected mode
    open_ports = []
    done = 0
    total = len(ports)

    # Pick scan function based on mode
    if mode == "syn":
        scan_func = lambda p: scan_syn_port(host, p, timeout)
        threads = min(threads, 100)  # SYN scan works better with fewer threads
    elif mode == "udp":
        scan_func = lambda p: scan_udp_port(host, p, timeout)
        threads = min(threads, 50)   # UDP needs more time per port
    else:
        scan_func = lambda p: scan_tcp_port(host, p, timeout)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_func, port): port for port in ports}

        for future in as_completed(futures):
            done += 1
            r = future.result()

            if r["status"] in ("OPEN", "OPEN|FILTERED"):
                open_ports.append(r)
                status_color = Fore.GREEN if r["status"] == "OPEN" else Fore.YELLOW
                print(
                    f"\r  {status_color}[{r['status']}]{Style.RESET_ALL}  "
                    f"{Fore.YELLOW}{r['port']:<6}{Style.RESET_ALL} "
                    f"{Fore.WHITE}{r['service']:<40}" + " " * 20
                )

            print(
                f"\r  {Fore.CYAN}Ports: {Fore.WHITE}{done}/{total}"
                f"{Fore.CYAN}  |  Open: {Fore.GREEN}{len(open_ports)}" + " " * 15,
                end="", flush=True
            )

    print()
    return sorted(open_ports, key=lambda x: x["port"])


# --- Main scan ---------------------------------------------------------------

def scan_range(host: str, ports: list, timeout: float = 0.5,
               threads: int = 200, mode: str = "tcp", output: str = None):
    # Scan a single host and print results
    total = len(ports)
    mode_color = {
        "tcp": Fore.BLUE, "syn": Fore.MAGENTA, "udp": Fore.YELLOW
    }.get(mode, Fore.WHITE)

    print(f"\n{Fore.CYAN}Scanning {Fore.WHITE}{host}"
          f"{Fore.CYAN} | ports: {Fore.WHITE}{total}"
          f"{Fore.CYAN} | threads: {Fore.WHITE}{threads}"
          f"{Fore.CYAN} | mode: {mode_color}{mode.upper()}")
    print(Fore.CYAN + "-" * 55)

    t_start = time.time()
    open_ports = scan_host(host, ports, timeout, threads, mode)
    elapsed = time.time() - t_start

    print("\n" + Fore.CYAN + "-" * 55)
    print(f"\n{Fore.CYAN}{'PORT':<8} {'MODE':<6} {'SERVICE'}")
    print(Fore.CYAN + "-" * 55)
    for p in open_ports:
        print(f"  {Fore.YELLOW}{p['port']:<6}{Style.RESET_ALL} "
              f"{Fore.CYAN}{p['mode']:<6}{Style.RESET_ALL} "
              f"{Fore.WHITE}{p['service']}")
    print(f"\n{Fore.CYAN}Time: {Fore.WHITE}{elapsed:.2f}s")
    print(f"{Fore.CYAN}Total open ports: {Fore.GREEN}{len(open_ports)}")

    if output:
        save_results(host, open_ports, elapsed, output, mode)


def scan_all_modes(host: str, ports: list, timeout: float = 0.5,
                   threads: int = 200, output: str = None):
    # Run TCP, SYN and UDP scans and combine results
    print(f"\n{Fore.CYAN}Mode ALL — running TCP + SYN + UDP")
    print(Fore.CYAN + "=" * 55)

    all_results = {}
    t_start = time.time()

    for mode in ["tcp", "syn", "udp"]:
        mode_color = {
            "tcp": Fore.BLUE, "syn": Fore.MAGENTA, "udp": Fore.YELLOW
        }[mode]
        print(f"\n{mode_color}[{mode.upper()}] scanning...")
        results = scan_host(host, ports, timeout, threads, mode)
        for r in results:
            key = (r["port"], mode)
            all_results[key] = r

    elapsed = time.time() - t_start
    combined = sorted(all_results.values(), key=lambda x: (x["port"], x["mode"]))

    print("\n" + Fore.CYAN + "=" * 55)
    print(f"\n{Fore.CYAN}{'PORT':<8} {'MODE':<6} {'SERVICE'}")
    print(Fore.CYAN + "-" * 55)
    for p in combined:
        print(f"  {Fore.YELLOW}{p['port']:<6}{Style.RESET_ALL} "
              f"{Fore.CYAN}{p['mode']:<6}{Style.RESET_ALL} "
              f"{Fore.WHITE}{p['service']}")
    print(f"\n{Fore.CYAN}Time: {Fore.WHITE}{elapsed:.2f}s")
    print(f"{Fore.CYAN}Total results: {Fore.GREEN}{len(combined)}")

    if output:
        save_results(host, combined, elapsed, output, "all")


# --- Save results ------------------------------------------------------------

def save_results(host: str, open_ports: list, elapsed: float,
                 output: str, mode: str = "tcp"):
    # Save results to JSON or CSV
    ext = os.path.splitext(output)[1].lower()

    if ext == ".json":
        data = {
            "host": host,
            "mode": mode,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_seconds": round(elapsed, 2),
            "total_open": len(open_ports),
            "ports": [{"port": p["port"], "mode": p["mode"],
                       "service": p["service"]} for p in open_ports]
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    elif ext == ".csv":
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["host", "port", "mode", "service",
                             "scan_time", "elapsed_seconds"])
            for p in open_ports:
                writer.writerow([host, p["port"], p["mode"], p["service"],
                                 time.strftime("%Y-%m-%d %H:%M:%S"),
                                 round(elapsed, 2)])
    else:
        print(f"{Fore.RED}Error: use .json or .csv")
        return

    print(f"{Fore.CYAN}Results saved: {Fore.WHITE}{output}")


# --- Subnet scan -------------------------------------------------------------

def ping_host(ip: str) -> bool:
    # Ping a host to check if it's online
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-w", "500", str(ip)]
    try:
        result = subprocess.run(
            command, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=2
        )
        return result.returncode == 0
    except Exception:
        return False


def get_hostname(ip: str) -> str:
    # Try to resolve hostname from IP
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        return ""


def sweep_subnet(subnet: str, threads: int = 100) -> list:
    # Ping all hosts in subnet and return list of online IPs
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        print(f"{Fore.RED}Error: invalid subnet format. Example: 192.168.1.0/24")
        return []

    hosts = list(network.hosts())
    total = len(hosts)
    online = []
    done = 0

    print(f"\n{Fore.CYAN}Scanning subnet {Fore.WHITE}{subnet}"
          f"{Fore.CYAN} | hosts: {Fore.WHITE}{total}")
    print(Fore.CYAN + "-" * 55)
    print(f"{Fore.CYAN}Step 1: finding live hosts (ping sweep)...")
    print(Fore.CYAN + "-" * 55)

    t_start = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(ping_host, str(ip)): str(ip) for ip in hosts}

        for future in as_completed(futures):
            done += 1
            ip = futures[future]
            is_online = future.result()

            if is_online:
                hostname = get_hostname(ip)
                label = f"{ip} ({hostname})" if hostname else ip
                online.append(ip)
                print(f"\r  {Fore.GREEN}[ONLINE]{Style.RESET_ALL}  "
                      f"{Fore.WHITE}{label:<50}")

            elapsed = time.time() - t_start
            speed = done / elapsed if elapsed > 0 else 0
            remaining = (total - done) / speed if speed > 0 else 0
            print(
                f"\r  {Fore.CYAN}Progress: {Fore.WHITE}{done}/{total}"
                f"{Fore.CYAN}  |  Remaining: {Fore.WHITE}{total - done}"
                f"{Fore.CYAN}  |  ~{Fore.WHITE}{remaining:.0f}s"
                f"{Fore.CYAN}  |  {Fore.WHITE}{speed:.0f} host/s" + " " * 10,
                end="", flush=True
            )

    print(f"\n{Fore.CYAN}-" * 55)
    print(f"{Fore.CYAN}Live hosts found: {Fore.GREEN}{len(online)}"
          f"{Fore.CYAN} in {Fore.WHITE}{time.time() - t_start:.2f}s")
    return online


def scan_subnet(subnet: str, ports: list, timeout: float = 0.5,
                threads: int = 200, mode: str = "tcp", output: str = None):
    # Scan all hosts in a subnet
    online_hosts = sweep_subnet(subnet, threads=100)

    if not online_hosts:
        print(f"{Fore.RED}No live hosts found.")
        return

    print(f"\n{Fore.CYAN}Step 2: scanning ports on each host...")
    print(Fore.CYAN + "-" * 55)

    all_results = {}
    t_start = time.time()

    for i, host in enumerate(online_hosts, 1):
        hostname = get_hostname(host)
        label = f"{host} ({hostname})" if hostname else host
        print(f"\n{Fore.CYAN}[{i}/{len(online_hosts)}] {Fore.WHITE}{label}")

        open_ports = scan_host(host, ports, timeout, threads, mode)
        all_results[host] = {"hostname": hostname, "open_ports": open_ports}

        if open_ports:
            print(f"  {Fore.CYAN}{'PORT':<8} {'MODE':<6} {'SERVICE'}")
            for p in open_ports:
                print(f"  {Fore.YELLOW}{p['port']:<6}{Style.RESET_ALL} "
                      f"{Fore.CYAN}{p['mode']:<6}{Style.RESET_ALL} "
                      f"{Fore.WHITE}{p['service']}")
        else:
            print(f"  {Fore.YELLOW}No open ports found")

    elapsed = time.time() - t_start
    print(f"\n{Fore.CYAN}{'=' * 55}")
    print(f"{Fore.CYAN}Subnet scan complete in {Fore.WHITE}{elapsed:.2f}s")
    print(f"{Fore.CYAN}Hosts online: {Fore.GREEN}{len(online_hosts)}")

    if output:
        save_subnet_results(subnet, all_results, elapsed, output)


def save_subnet_results(subnet: str, results: dict,
                        elapsed: float, output: str):
    # Save subnet scan results to JSON or CSV
    ext = os.path.splitext(output)[1].lower()

    if ext == ".json":
        data = {
            "subnet": subnet,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_seconds": round(elapsed, 2),
            "hosts": {
                ip: {
                    "hostname": info["hostname"],
                    "open_ports": [{"port": p["port"], "mode": p["mode"],
                                   "service": p["service"]}
                                  for p in info["open_ports"]]
                }
                for ip, info in results.items()
            }
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    elif ext == ".csv":
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "hostname", "port", "mode",
                             "service", "scan_time"])
            for ip, info in results.items():
                for p in info["open_ports"]:
                    writer.writerow([ip, info["hostname"], p["port"],
                                    p["mode"], p["service"],
                                    time.strftime("%Y-%m-%d %H:%M:%S")])

    print(f"{Fore.CYAN}Results saved: {Fore.WHITE}{output}")


# --- Entry point -------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Network port scanner — TCP / SYN / UDP",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--host", help="Target host (IP or domain)")
    parser.add_argument("--subnet", help="Target subnet in CIDR notation\nExample: 192.168.1.0/24")
    parser.add_argument("--ports", default="1-1024",
                        help="Ports to scan\nExamples: 1-1024 | 80,443,22 | 22,80,100-200\nDefault: 1-1024")
    parser.add_argument("--threads", type=int, default=200,
                        help="Number of threads (default: 200)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Timeout in seconds (default: 0.5)")
    parser.add_argument("--mode", default="tcp", choices=["tcp", "syn", "udp", "all"],
                        help="Scan mode: tcp | syn | udp | all\nDefault: tcp")
    parser.add_argument("--output",
                        help="Save results to file\nExamples: results.json | results.csv")

    args = parser.parse_args()

    if not args.host and not args.subnet:
        print(f"{Fore.RED}Error: provide --host or --subnet")
        return

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print(f"{Fore.RED}Error: invalid port format. Examples: 1-1024 | 80,443 | 22,80,100-200")
        return

    if args.subnet:
        scan_subnet(args.subnet, ports, timeout=args.timeout,
                    threads=args.threads, mode=args.mode, output=args.output)
    elif args.mode == "all":
        scan_all_modes(args.host, ports, timeout=args.timeout,
                       threads=args.threads, output=args.output)
    else:
        scan_range(args.host, ports, timeout=args.timeout,
                   threads=args.threads, mode=args.mode, output=args.output)


if __name__ == "__main__":
    main()