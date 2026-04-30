
"""Generates a sample access.log for testing the parser."""
import random, datetime

ips = [
    "192.168.1.100",   # normal user
    "10.0.0.55",       # normal user
    "185.220.101.42",  # attacker (many failed attempts)
    "45.33.32.156",    # attacker
    "203.0.113.99",    # occasional visitor
]

paths = ["/", "/login", "/admin", "/wp-login.php", "/index.html", "/api/v1/users"]

lines = []
base = datetime.datetime(2024, 4, 10, 12, 0, 0)

for i in range(200):
    ts = base + datetime.timedelta(seconds=i * 3)
    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")

    ip = random.choice(ips)
    path = random.choice(paths)
    method = "GET" if random.random() > 0.3 else "POST"

    # Attacker IPs receive 401 more often
    if ip in ("185.220.101.42", "45.33.32.156"):
        status = random.choice([401, 401, 401, 403, 200])
    else:
        status = random.choice([200, 200, 200, 301, 404])

    size = random.randint(200, 5000)
    lines.append(
        f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {size}'
    )

with open("access.log", "w") as f:
    f.write("\n".join(lines) + "\n")

print("access.log created (200 lines)")
