# NetPortScanner

A fast multi-threaded network port scanner written in Python. Supports TCP, SYN, and UDP scanning with banner grabbing, subnet discovery, and export to JSON/CSV.

## Features

- **TCP Connect scan** — standard connection scan
- **SYN scan** — half-open scan, harder to detect by firewalls
- **UDP scan** — detects UDP services
- **Banner grabbing** — identifies service name and version (e.g. `SSH-2.0-OpenSSH_6.6.1p1`)
- **Subnet scan** — ping sweep to find live hosts, then scan each one
- **Export** — save results to JSON or CSV
- **Color output** — open ports highlighted in green
- **High speed** — up to 7000+ ports/sec on localhost with 5000 threads

## Requirements

```bash
pip install colorama scapy
```

Download and install **[Npcap](https://npcap.com/#download)** for SYN and UDP scanning on Windows.

## Usage

```bash
# Basic TCP scan
python NetPortScanner.py --host localhost --ports 1-1024

# Full port range
python NetPortScanner.py --host localhost --ports 1-65535 --threads 1000

# SYN scan (run as Administrator)
python NetPortScanner.py --host scanme.nmap.org --ports 1-1024 --mode syn

# UDP scan (run as Administrator)
python NetPortScanner.py --host scanme.nmap.org --ports 1-1024 --mode udp --timeout 2

# All three modes at once
python NetPortScanner.py --host scanme.nmap.org --ports 1-1024 --mode all

# Specific ports
python NetPortScanner.py --host 192.168.1.1 --ports 22,80,443,3306,3389

# Subnet scan
python NetPortScanner.py --subnet 192.168.1.0/24 --ports 1-1024

# Save to JSON
python NetPortScanner.py --host localhost --ports 1-65535 --output results.json

# Save to CSV
python NetPortScanner.py --host localhost --ports 1-65535 --output results.csv
```

## Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--host` | Target IP address or domain | — |
| `--subnet` | Target subnet in CIDR notation | — |
| `--ports` | Port range `1-1024`, list `80,443,22`, or combined `22,80,100-200` | `1-1024` |
| `--threads` | Number of parallel threads | `200` |
| `--timeout` | Connection timeout in seconds | `0.5` |
| `--mode` | Scan mode: `tcp` / `syn` / `udp` / `all` | `tcp` |
| `--output` | Output file path — `.json` or `.csv` | — |

## Example Output

```
Scanning scanme.nmap.org | ports: 1024 | threads: 500 | mode: ALL
-------------------------------------------------------
  [OPEN]  22     SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  [OPEN]  22     SSH
  [OPEN|FILTERED]  53    DNS
  [OPEN|FILTERED]  123   NTP

PORT     MODE   SERVICE
-------------------------------------------------------
  22     TCP    SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  22     SYN    SSH
  53     UDP    DNS
  123    UDP    NTP
  500    UDP    IKE VPN

Time: 28.54s
Total results: 5
```

## JSON Output Format

```json
{
  "host": "scanme.nmap.org",
  "mode": "all",
  "scan_time": "2026-04-29 10:34:46",
  "elapsed_seconds": 28.54,
  "total_open": 5,
  "ports": [
    {"port": 22, "mode": "TCP", "service": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"},
    {"port": 22, "mode": "SYN", "service": "SSH"},
    {"port": 53, "mode": "UDP", "service": "DNS"}
  ]
}
```

## Performance

| Threads | Ports | Time |
|---------|-------|------|
| 200 | 65535 | ~35s |
| 1000 | 65535 | ~9s |


Tested on Intel Core i9-14900K.

## Legal

> Only scan hosts and networks you own or have **explicit written permission** to scan.
> Unauthorized port scanning may be illegal in your country.
> The author is not responsible for any misuse of this tool.

## Author

**Mykhailo Vlasov**

Built as a learning project — from basic socket connection to a full TCP/SYN/UDP scanner with subnet discovery and banner grabbing.