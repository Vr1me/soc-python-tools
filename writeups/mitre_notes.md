# MITRE ATT&CK Study Notes

## What is MITRE ATT&CK?
A globally accessible knowledge base of adversary tactics and techniques based on real-world observations. Used by SOC analysts to understand, detect and respond to attacks.

## Key Components

### Tactics — the "WHY"
What attacker wants to achieve. 14 tactics in Enterprise matrix:
1. Reconnaissance
2. Resource Development
3. Initial Access
4. Execution
5. Persistence
6. Privilege Escalation
7. Defense Evasion
8. Credential Access
9. Discovery
10. Lateral Movement
11. Collection
12. Command & Control
13. Exfiltration
14. Impact

### Techniques — the "HOW"
How attacker achieves their goal.
Example: T1566 — Phishing (under Initial Access)

### Sub-techniques — specific methods
Example: T1566.001 — Spearphishing Attachment

### Procedures
Real-world implementation by a specific threat actor.

## Who Uses ATT&CK?
- SOC Analysts — link alerts to tactics/techniques
- CTI Teams — map threat actor behavior to TTPs
- Detection Engineers — map SIEM rules to ATT&CK
- Incident Responders — map attack timeline
- Red Teams — build attack emulation plans

## MITRE CAR
Cyber Analytics Repository — ready-made detection analytics built on ATT&CK.
- Provides Splunk/EQL queries for detecting TTPs
- Translates ATT&CK techniques into real SIEM detections
- Link: https://car.mitre.org

## MITRE D3FEND
Defensive counterpart to ATT&CK — maps defensive techniques.
Full name: Detection, Denial, and Disruption Framework Empowering Network Defense

### 7 D3FEND Tactics:
1. Model — understand your environment
2. Harden — reduce attack surface
3. Detect — identify malicious activity
4. Isolate — contain attacker movement
5. Deceive — mislead attacker with honeypots
6. Evict — remove attacker from environment
7. Restore — recover after attack

## ATT&CK vs CAR vs D3FEND
| Framework | Purpose |
|---|---|
| ATT&CK | What attackers do |
| CAR | How to detect it in SIEM |
| D3FEND | How to stop it |

## Real Example — Mustang Panda (G0129)
- Initial Access: Phishing
- Persistence: Scheduled Tasks
- Defense Evasion: Obfuscate files
- C2: Ingress Tool Transfer

## Top 10 Techniques to Know
| ID | Technique |
|---|---|
| T1566 | Phishing |
| T1550 | Pass-the-Hash |
| T1110 | Brute Force |
| T1059 | PowerShell |
| T1547 | Registry Run Keys |
| T1003 | Credential Dumping |
| T1021 | Remote Services RDP |
| T1041 | Exfiltration |
| T1071 | C2 via HTTP/HTTPS |
| T1053 | Scheduled Task |