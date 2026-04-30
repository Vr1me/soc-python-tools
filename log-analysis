#!/usr/bin/env python3
"""
Log Parser -- Brute Force Detector
Parses Apache/Nginx access.log and SSH auth.log.
Detects brute force attacks and saves alerts to CSV.
"""

import re
import csv
import argparse
import sys
from collections import Counter
from datetime import datetime


# ─── Regex Patterns ──────────────────────────────────────────────────────────

# Apache/Nginx access.log format:
# 192.168.1.1 - - [10/Apr/2024:13:55:36 +0000] "GET /login HTTP/1.1" 401 512
APACHE_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'     # IP address
    r'[^\[]*'
    r'\[(?P<timestamp>[^\]]+)\]'            # Timestamp in brackets
    r'[^"]*"'
    r'(?P<method>\w+)\s+'                   # HTTP method (GET, POST...)
    r'(?P<path>\S+)[^"]*"'                  # Request path
    r'\s+(?P<status>\d{3})'                 # HTTP status code
)

# SSH auth.log format:
# Apr 10 13:55:36 server sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2
AUTH_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)' # Timestamp: "Apr 10 13:55:36"
    r'.+?'
    r'(?P<status>Failed|Accepted)'          # Login result
    r'\s+\w+\s+for\s+\S+\s+from\s+'
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'     # IP address
)


# ─── Line Parser ─────────────────────────────────────────────────────────────

def parse_line(line: str) -> dict | None:
    """
    Try to match a log line against known formats.
    Returns a dict with ip, timestamp, status, path, type -- or None if no match.
    """
    # Try Apache/Nginx format first
    m = APACHE_PATTERN.search(line)
    if m:
        return {
            "ip":        m.group("ip"),
            "timestamp": m.group("timestamp"),
            "status":    m.group("status"),
            "path":      m.group("path"),
            "type":      "apache",
        }

    # Try SSH auth.log format
    m = AUTH_PATTERN.search(line)
    if m:
        return {
            "ip":        m.group("ip"),
            "timestamp": m.group("timestamp"),
            "status":    "401" if m.group("status") == "Failed" else "200",
            "path":      "ssh",
            "type":      "auth",
        }

    return None


# ─── Main Analysis ────────────────────────────────────────────────────────────

def analyze(log_file: str, threshold: int = 5, top_n: int = 10, debug: bool = False):
    total_lines  = 0
    parsed_lines = 0
    skipped      = 0

    ip_total  = Counter()  # total requests per IP
    ip_failed = Counter()  # failed requests per IP (status 4xx / 5xx)
    alerts    = []

    print(f"\n{'='*58}")
    print(f"  [*]  Analyzing: {log_file}")
    print(f"  [*]  Threshold: {threshold} failed attempts")
    print(f"{'='*58}\n")

    # Open the file -- show a clear error if it does not exist
    try:
        f = open(log_file, "r", errors="ignore")
    except FileNotFoundError:
        print(f"  [ERROR]  File not found: {log_file}")
        print(f"  [INFO]   Run 'python generate_test_log.py' to create a sample log.")
        sys.exit(1)

    with f:
        for line in f:
            line = line.rstrip("\n")
            total_lines += 1

            if not line.strip():
                continue  # skip blank lines

            entry = parse_line(line)

            if not entry:
                skipped += 1
                if debug:
                    print(f"  [DEBUG] No match: {line[:80]}")
                continue

            parsed_lines += 1
            ip     = entry["ip"]
            status = entry["status"]

            ip_total[ip] += 1

            # Count failed attempts (HTTP 4xx and 5xx)
            if status.startswith(("4", "5")):
                ip_failed[ip] += 1

                # Fire the alert exactly once per IP when threshold is crossed
                if ip_failed[ip] == threshold + 1:
                    alert = {
                        "detected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "ip":          ip,
                        "attempts":    ip_failed[ip],
                        "alert_type":  "Brute Force",
                    }
                    alerts.append(alert)
                    print(f"  [ALERT]  Brute Force suspected -- {ip}  "
                          f"({ip_failed[ip]} failed attempts)")

    # ── Top N IPs ─────────────────────────────────────────────────────────────
    print(f"\n{'-'*58}")
    print(f"  [+]  Top {top_n} IPs by total requests:")
    print(f"{'-'*58}")

    if not ip_total:
        print("  [!]  No IPs found. Use --debug to see why lines were skipped.")
    else:
        for rank, (ip, count) in enumerate(ip_total.most_common(top_n), 1):
            failed = ip_failed.get(ip, 0)
            tag    = "  <-- SUSPICIOUS" if failed > threshold else ""
            print(f"  {rank:>2}. {ip:<18}  {count:>5} requests  "
                  f"({failed} failed){tag}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'-'*58}")
    print(f"  [i]  Total lines :  {total_lines}")
    print(f"  [i]  Parsed      :  {parsed_lines}")
    print(f"  [i]  Skipped     :  {skipped}")
    print(f"  [i]  Alerts      :  {len(alerts)}")
    print(f"{'='*58}\n")

    return alerts


# ─── Save Alerts to CSV ───────────────────────────────────────────────────────

def save_csv(alerts: list, output: str = "alerts.csv"):
    """Write all alerts to a CSV file with timestamp."""
    if not alerts:
        print("  [i]  No alerts detected -- CSV not created.\n")
        return

    fieldnames = ["detected_at", "ip", "attempts", "alert_type"]
    with open(output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"  [+]  Alerts saved to: {output}\n")


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Log Parser -- Brute Force Detector for SOC use"
    )
    parser.add_argument(
        "--file", "-f",
        default="access.log",
        help="Path to log file (default: access.log)"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=5,
        help="Number of failed attempts before alert fires (default: 5)"
    )
    parser.add_argument(
        "--top", "-n",
        type=int,
        default=10,
        help="How many top IPs to display (default: 10)"
    )
    parser.add_argument(
        "--output", "-o",
        default="alerts.csv",
        help="Output CSV filename (default: alerts.csv)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print lines that failed to parse (useful for troubleshooting)"
    )
    args = parser.parse_args()

    alerts = analyze(
        args.file,
        threshold=args.threshold,
        top_n=args.top,
        debug=args.debug,
    )
    save_csv(alerts, output=args.output)


if __name__ == "__main__":
    main()
