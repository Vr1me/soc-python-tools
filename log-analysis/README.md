# log_parser.py

A SOC tool for analyzing Apache/Nginx access logs and SSH auth logs.  
Detects brute force attacks, ranks suspicious IPs, and saves alerts to CSV.

## Features

- Parses Apache/Nginx `access.log` and Linux `auth.log`
- Extracts IP address, timestamp, and status code using regex
- Counts requests per IP using `collections.Counter`
- Fires `[ALERT]` when a single IP exceeds the failed attempt threshold
- Displays top N IPs by total request count
- Saves all alerts to a CSV file with timestamp
- `--debug` flag to troubleshoot unmatched lines

## Usage

```bash
# Basic run against access.log
python log_parser.py --file access.log

# Custom threshold (default is 5)
python log_parser.py --file access.log --threshold 3

# Custom output file
python log_parser.py --file access.log --output my_alerts.csv

# Show top 20 IPs instead of 10
python log_parser.py --file access.log --top 20

# Debug mode — prints lines that failed to parse
python log_parser.py --file access.log --debug
```

## Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--file` | `-f` | `access.log` | Path to log file |
| `--threshold` | `-t` | `5` | Failed attempts before alert fires |
| `--top` | `-n` | `10` | Number of top IPs to display |
| `--output` | `-o` | `alerts.csv` | Output CSV filename |
| `--debug` | | off | Print lines that failed to parse |

## Example Output

```
==========================================================
  [*]  Analyzing: access.log
  [*]  Threshold: 5 failed attempts
==========================================================

  [ALERT]  Brute Force suspected -- 185.220.101.42  (6 failed attempts)
  [ALERT]  Brute Force suspected -- 45.33.32.156    (6 failed attempts)

----------------------------------------------------------
  [+]  Top 10 IPs by total requests:
----------------------------------------------------------
   1. 185.220.101.42      52 requests  (38 failed)  <-- SUSPICIOUS
   2. 192.168.1.100       44 requests  (3 failed)
   3. 45.33.32.156        41 requests  (31 failed)  <-- SUSPICIOUS
   4. 10.0.0.55           38 requests  (2 failed)

----------------------------------------------------------
  [i]  Total lines :  200
  [i]  Parsed      :  200
  [i]  Skipped     :  0
  [i]  Alerts      :  2
==========================================================

  [+]  Alerts saved to: alerts.csv
```

## CSV Output Format

| Field | Description |
|-------|-------------|
| `detected_at` | Timestamp when alert was triggered |
| `ip` | Source IP address |
| `attempts` | Number of failed attempts |
| `alert_type` | Type of attack detected |

Example:
```
detected_at,ip,attempts,alert_type
2026-04-30 11:21:00,185.220.101.42,6,Brute Force
2026-04-30 11:21:00,45.33.32.156,6,Brute Force
```

## Supported Log Formats

**Apache/Nginx access.log:**
```
192.168.1.1 - - [10/Apr/2024:13:55:36 +0000] "GET /login HTTP/1.1" 401 512
```

**Linux SSH auth.log:**
```
Apr 10 13:55:36 server sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2
```

## Generate Test Data

```bash
# Creates a sample access.log with 200 lines including simulated attacks
python generate_test_log.py
```

## Real-World Use

This tool replicates basic functionality used in SOC environments:
- First-pass triage of web server logs during an incident
- Identifying IPs to block at the firewall
- Building evidence for incident reports
