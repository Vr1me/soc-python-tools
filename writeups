# HTB — Dancing (SMB Enumeration)

## Overview
- OS: Windows
- Difficulty: Very Easy
- Category: Starting Point
- Key skill: SMB enumeration and unauthenticated share access

## Reconnaissance
Started with an Nmap service scan to identify open ports:

nmap -sV 10.129.111.112

Results:
- Port 135/tcp — Microsoft RPC
- Port 139/tcp — NetBIOS
- Port 445/tcp — SMB (Microsoft-DS)
- OS detected: Windows

Port 445 (SMB) is the primary target — 
it is commonly misconfigured and has been 
exploited in major attacks such as WannaCry (2017).

## Enumeration
Listed available SMB shares without credentials:

smbclient -L 10.129.111.112

Discovered shares:
- ADMIN$ — Remote Admin (default)
- C$ — Default share (default)
- IPC$ — Remote IPC (default)
- WorkShares — Non-default share (interesting!)

WorkShares stood out as a non-default share 
— worth investigating further.

## Exploitation
Connected to WorkShares without a password:

smbclient \\\\10.129.111.112\\WorkShares

No password required — anonymous access enabled.
This is a critical misconfiguration.

Inside found two user directories:
- Amy.J
- James.P

Navigated to James.P directory and found flag:

cd James.P
ls
get flag.txt
exit

## Flag
Retrieved the root flag from James.P directory.

## SOC Relevance
As a SOC analyst, open SMB shares are a 
critical red flag:
- Port 445 open externally = immediate investigation
- Anonymous SMB access = data exposure risk
- Check with: smbclient -L <ip>
- MITRE ATT&CK: T1021.002 — SMB/Windows Admin Shares

## Lessons Learned
- Always enumerate non-default shares
- Anonymous SMB access is a critical misconfiguration
- Default credentials and empty passwords 
  are still common in real environments
- SMB misconfigurations were exploited in 
  WannaCry (2017) and NotPetya attacks

## Commands Used
nmap -sV 10.129.111.112
smbclient -L 10.129.111.112
smbclient \\\\10.129.111.112\\WorkShares
cd James.P
ls
get flag.txt