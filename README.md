# PowerAudit

Offline Windows Compliance & Security Scanner
A lightweight, PowerShell-based tool for fast local vulnerability assessment.



## What is PowerAudit?

PowerAudit is a non-intrusive, offline security audit script for Windows systems.
It checks key security configurations — firewall, antivirus, RDP, SMBv1, open ports, account policies — and displays a detailed report directly in the terminal.
Originally designed for Bash Bunny or Rubber Ducky payloads, but runs standalone as well.



## 📊 Features
	•	✅ Firewall Status Check (Domain / Private / Public)
 
	•	✅ Antivirus Detection & Status
 
	•	✅ OS Update Level (Latest Hotfix Installed)
 
	•	✅ SMBv1 Protocol Detection (Legacy / Unsafe)
 
	•	✅ RDP Status Check
 
	•	✅ User Account Control (UAC) Status
 
	•	✅ Guest Account Status
 
	•	✅ Passwordless Accounts Detection
 
	•	✅ Open TCP Ports & Listening Services
 
	•	✅ Built-in Administrator Status
 
	•	🔒 No Data Stored – Report shown in-terminal only
 
	•	🛠️ Offline, Safe, and Read-Only
 

 ## Example Report
 ```
===== Vulnerability Scan Report for WIN10-SECURE =====
OS Version: Windows 10 Pro (Version 10.0.19045)
Latest Hotfix: KB5035853 (installed on 07/15/2025)

Firewall Profiles: Domain=Enabled ✅; Private=Enabled ✅; Public=Enabled ✅
Antivirus: Windows Defender – State: On, Signatures: Up-to-date
SMBv1 Protocol: Disabled ✅
Remote Desktop (RDP): ENABLED ⚠️
User Account Control (UAC): Enabled ✅
Guest Account: Disabled ✅
Built-in Administrator: Enabled ⚠️
Password Policy: All enabled local accounts require a password
Open Listening Ports:
 - Port 135 (svchost)
 - Port 445 (System)
 - Port 3389 (svchost)
 - Port 5985 (wsmprovhost)

===== END OF SECURITY AUDIT =====
```

## Standalone
	1.	Copy ComplianceAudit.ps1 to the target machine.
	2.	Open PowerShell (as Administrator recommended).
	3.	Run: 
 ```
 powershell -ExecutionPolicy Bypass -File ComplianceAudit.ps1
 ```
  4.	View the compliance report directly in the terminal.
     
Bash Bunny Deployment (Optional)
	1.	Place ComplianceAudit.ps1 on your Bash Bunny storage.
	2.	Use the following in your payload.txt:
 ```
LED SETUP
ATTACKMODE HID
LED ATTACK
QUACK STRING powershell -WindowStyle hidden -ExecutionPolicy Bypass -File C:\Windows\Temp\ComplianceAudit.ps1
QUACK ENTER
LED FINISH
```
  3.	Payload injects script via HID keyboard emulation.

(Adapt paths as needed.)

## ⚠️ Disclaimer

PowerAudit is strictly intended for:
	•	Authorized use
	•	Security auditing
	•	Compliance assessments
Do not deploy this tool on machines without explicit permission.

This script is:
	•	Read-only (no system modifications)
	•	Offline (no external data sent)
	•	Provided as-is, without warranty.

