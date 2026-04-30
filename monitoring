import re
import csv
from collections import Counter

# Configuration
LOG_FILE = 'auth.log'       # Path to the authentication log file
REPORT_FILE = 'failed_logins.csv'
THRESHOLD = 5               # Alert threshold for failed attempts

def analyze_logins():
    """
    Parses auth.log to find failed login attempts, counts them by IP,
    and saves the suspicious activity to a CSV report.
    """
    failed_attempts = []
    
    # Regex pattern to match "Failed password" and extract the source IP address
    # Example log: Oct 10 12:10:05 host sshd: Failed password for root from 192.168.1.105 port 22
    pattern = re.compile(r"Failed password for .* from ([\d\.]+)")

    try:
        # Open and read the log file line by line for memory efficiency
        with open(LOG_FILE, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    # Append found IP to the list
                    failed_attempts.append(match.group(1))
    except FileNotFoundError:
        print(f"Error: {LOG_FILE} not found. Please ensure the file exists.")
        return

    # Count occurrences of each IP address
    ip_counts = Counter(failed_attempts)

    # Prepare to write results to CSV and display in console
    try:
        with open(REPORT_FILE, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # Write CSV Header
            writer.writerow(['IP Address', 'Failed Attempts', 'Status'])

            print(f"{'IP Address':<15} | {'Count':<5} | {'Status'}")
            print("-" * 40)

            for ip, count in ip_counts.items():
                # Flag as WARNING if count exceeds the threshold
                if count > THRESHOLD:
                    status = "WARNING"
                    # Print in Red color for better visibility in terminal
                    print(f"\033[91m{ip:<15} | {count:<5} | {status}\033[0m")
                else:
                    status = "NORMAL"
                    print(f"{ip:<15} | {count:<5} | {status}")
                
                # Write record to the CSV file
                writer.writerow([ip, count, status])

        print(f"\n[+] Analysis complete. Report saved: {REPORT_FILE}")

    except PermissionError:
        print(f"Error: Permission denied when writing to {REPORT_FILE}")

if __name__ == "__main__":
    analyze_logins()
