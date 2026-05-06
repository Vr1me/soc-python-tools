# SOC Python Tools

A growing collection of Python scripts for SOC Analyst tasks — built while studying cybersecurity and completing HackTheBox machines.

## Structure

```
soc-python-tools/
├── folder-monitor-vt/  # Real-time folder monitor with VirusTotal API
├── log-analysis/       # Log parsing and brute force detection
├── network/            # Port scanning, DNS, network recon
├── monitoring/         # Auth log monitoring and alerting
├── writeups/           # HackTheBox writeups and study notes
└── samples/            # Sample log files for testing
```

## Tools

### Folder Monitor + VirusTotal ⭐
| Script | Description |
|--------|-------------|
| [`folder-monitor-vt/`](folder-monitor-vt/) | Watches a folder in real time. On new file: computes SHA256, queries VirusTotal API, raises ALERT if any AV engine flags the file. Tested against EICAR (53/59 detections) |

### Log Analysis
| Script | Description |
|--------|-------------|
| `log_parser.py` | Parses Apache/Nginx access.log and auth.log — detects brute force attacks, outputs top IPs, saves alerts to CSV |
| `log_search.py` | Searches for keywords in log files and outputs matching lines |
| `generate_test_log.py` | Generates sample access.log for testing |

### Network
| Script | Description |
|--------|-------------|
| `NetPortScanner.py` | TCP/SYN/UDP port scanner with banner grabbing and subnet scan |
| `nmap_scan.py` | Automates Nmap scanning and saves results to a file |
| `dns_lookup.py` | Resolves domain names to IP addresses |

### Monitoring
| Script | Description |
|--------|-------------|
| `auth_monitor.py` | Analyzes Linux auth.log — detects SSH brute force by IP, flags IPs over threshold, exports CSV report |

## Usage

```bash
# Real-time folder monitoring with VirusTotal
cd folder-monitor-vt
pip install -r requirements.txt
cp .env.example .env   # add your VirusTotal API key
python monitor.py

# Detect brute force attacks in a log file
python log-analysis/log_parser.py --file access.log

# Custom threshold and output
python log-analysis/log_parser.py --file access.log --threshold 3 --output alerts.csv

# Monitor SSH auth logs
python monitoring/auth_monitor.py

# Run port scanner
python network/NetPortScanner.py

# DNS lookup
python network/dns_lookup.py
```

## HackTheBox Writeups
- [Starting Point](writeups/htb-starting-point.md)
- [Dancing](writeups/htb-dancing-writeup.md)

## Study Notes
- [MITRE ATT&CK](writeups/mitre_notes.md) — Tactics, Techniques, CAR, D3FEND

## Author
**Mykhailo Vlasov** — Junior SOC Analyst  
GitHub: [github.com/Vr1me](https://github.com/Vr1me)