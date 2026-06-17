# Splunk SOC Home Lab

A home Security Operations Center (SOC) lab built to simulate real-world threat detection using Splunk Enterprise, Sysmon, and MITRE ATT&CK validated attack simulations.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| SIEM | Splunk Enterprise (Developer License) |
| Endpoint Monitoring | Sysmon |
| Log Sources | Windows Security, System, Application, Sysmon |
| Attack Simulation | Invoke-AtomicRedTeam |
| Detection Framework | MITRE ATT&CK |
| Host OS | Windows 11 (JBs_DESKTOP26) |
| VM | Windows 10 (VirtualBox) |

---

## Dashboards Built

### Dashboard 1 — Failed Login & Brute Force Monitor
Monitors authentication events across all hosts to detect brute force attacks and suspicious login patterns.

| Panel | Detection Logic | EventCode |
|-------|----------------|-----------|
| Failed Login Timeline | Hourly timechart of 4625 events | 4625 |
| Top Targeted Accounts | Accounts with most failures | 4625 |
| Failed Logins by Source | Source workstation analysis | 4625 |
| Brute Force Alert | Accounts with 10+ failures | 4625 |

### Dashboard 2 — Process Creation & Suspicious Execution Monitor
Monitors endpoint process activity to detect malware execution, suspicious parent-child relationships, and rare process launches.

| Panel | Detection Logic | EventCode |
|-------|----------------|-----------|
| Process Timeline | Hourly process creation volume | Sysmon 1 |
| Suspicious Path Execution | Processes from Temp/Downloads/AppData | Sysmon 1 |
| Parent-Child Anomaly | Office/Browser spawning shells | Sysmon 1 |
| Rare Process Execution | Processes running fewer than 3 times | Sysmon 1 |

---

## Attack Simulations — MITRE ATT&CK Validated

| # | Technique | Tactic | Tool | Result |
|---|-----------|--------|------|--------|
| 1 | T1059.001 — PowerShell Execution | Execution | Mimikatz via Atomic Red Team | Detected |
| 2 | T1082 — System Information Discovery | Discovery | Atomic Red Team | Detected |

Full details in [Attack Simulation Report](reports/ATTACK_SIMULATION_REPORT.md)

---

## Detection Queries

All SPL queries used in this project are documented here:[Detection Queries](queries/detection_queries.md)

---

## Key Skills Demonstrated

- Splunk SPL query writing and dashboard creation
- Windows Event Log analysis (Security, Sysmon)
- Sysmon deployment and configuration
- MITRE ATT&CK technique detection and mapping
- Attack simulation using Invoke-AtomicRedTeam
- Incident detection documentation and reporting
- Brute force detection logic
- Process execution anomaly detection
- Parent-child process relationship analysis
- Threat hunting using rare process frequency analysis

---

## Screenshots

All evidence screenshots are in the [screenshots](screenshots/) folder.

---

## Project Structure

```
splunk-soc-home-lab/
├── README.md
├── queries/
│   └── detection_queries.md
├── reports/
│   └── ATTACK_SIMULATION_REPORT.md
└── screenshots/
    └── [all evidence screenshots]
```
