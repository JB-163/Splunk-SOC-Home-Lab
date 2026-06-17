# SOC Lab — Detection Queries

## Dashboard 1 — Failed Login & Brute Force Monitor

### Panel 1 — Failed Login Timeline
```
index=wineventlog source="WinEventLog:Security" EventCode=4625
| timechart span=1h count as "Failed Logins"
```

### Panel 2 — Top Targeted Accounts
```
index=wineventlog source="WinEventLog:Security" EventCode=4625
| stats count as attempt_count by Account_Name
| sort -attempt_count
| head 10
```

### Panel 3 — Failed Logins by Source Workstation
```
index=wineventlog source="WinEventLog:Security" EventCode=4625
| stats count as attempt_count by Workstation_Name
| sort -attempt_count
| head 10
```

### Panel 4 — Brute Force Detection (10+ Failures)
```
index=wineventlog source="WinEventLog:Security" EventCode=4625
| stats count as failed_attempts by Account_Name, Workstation_Name
| where failed_attempts >= 10
| sort -failed_attempts
```

---

## Dashboard 2 — Process Creation & Suspicious Execution Monitor

### Panel 1 — Process Creation Timeline
```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host="JBs_DESKTOP26" EventCode=1
| timechart span=1h count as "Processes Created"
```

### Panel 2 — Processes Running from Suspicious Locations
```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host="JBs_DESKTOP26" EventCode=1
| eval suspicious=if(match(Image, "(?i)(\\Downloads\\|\\Temp\\|\\AppData\\|\\Desktop\\|\\Public\\)"), "YES", "NO")
| where suspicious="YES"
| table _time, User, Image, CommandLine, ParentImage
| sort -_time
```

### Panel 3 — Suspicious Parent-Child Process Relationships
```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host="JBs_DESKTOP26" EventCode=1
| eval suspicious_parent=if(match(ParentImage, "(?i)(winword\.exe|excel\.exe|powerpnt\.exe|chrome\.exe|firefox\.exe|msedge\.exe|outlook\.exe|powershell\.exe|cmd\.exe)"), "YES", "NO")
| eval suspicious_child=if(match(Image, "(?i)(cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe|mimikatz\.exe)"), "YES", "NO")
| where suspicious_parent="YES" AND suspicious_child="YES"
| table _time, User, ParentImage, Image, CommandLine
| sort -_time
```

### Panel 4 — Rare Process Execution
```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host="JBs_DESKTOP26" EventCode=1
| stats count as execution_count, values(CommandLine) as CommandLine, values(User) as User by Image
| where execution_count < 3
| sort execution_count
| table Image, execution_count, User, CommandLine
```
