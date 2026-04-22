# SOC Python Tools

Collection of Python scripts for SOC Analyst tasks.

## Scripts

### dns_lookup.py
Resolves domain names to IP addresses.
Usage: python dns_lookup.py

### log_search.py
Searches for keywords in log files and outputs matching lines.
Usage: python log_search.py

### nmap_scan.py
Runs Nmap scan on a target and saves results to a file.
Usage: python nmap_scan.py

## Study Notes
[MITRE ATT&CK Notes](mitre_notes.md) — Tactics, Techniques, CAR, D3FEND

### auth_monitor.py
Analyzes Linux `auth.log` files to detect SSH brute-force attempts.
- Identifies failed login attempts and groups them by IP address.
- Flags IPs exceeding a threshold with a WARNING status.
- Exports analysis results to a CSV report.
Usage: python auth_monitor.py


## Author
Mykhailo Vlasov — Junior SOC Analyst
GitHub: github.com/Vr1me