import subprocess

target = "scanme.nmap.org"
output_file = "nmap_results.txt"

print(f"Scanning {target}...")

result = subprocess.run(
    ["nmap", "-sV", target],
    capture_output=True,
    text=True
)

with open(output_file, "w") as f:
    f.write(result.stdout)

print(f"Scan complete! Results saved to {output_file}")
print(result.stdout)