# MITRE ATT&CK Coverage Matrix

> Maps every detection rule in this lab to the MITRE ATT&CK framework.
> Reference: https://attack.mitre.org

---

## Coverage Summary

| Tactic | Techniques Covered | Detection Files |
|--------|--------------------|-----------------|
| Initial Access | T1190 | sql_injection_detection.spl |
| Execution | T1059.007 | sql_injection_detection.spl |
| Credential Access | T1110, T1110.001, T1110.003 | brute_force_detection.spl |
| Privilege Escalation | T1078, T1078.001, T1078.003 | privilege_escalation.spl |
| Lateral Movement | T1021, T1021.001, T1021.002 | lateral_movement.spl |
| Command and Control | T1071.001, T1071.004, T1573.001 | C2 detections via proxy logs |
| Exfiltration | T1048.001, T1048.003, T1567 | data_exfiltration.spl |

Total: 5 Tactics, 9 Techniques, 5 Detection Files, 15 SPL Searches

---

## Detailed Technique Mapping

### TA0001 — Initial Access

**T1190 — Exploit Public-Facing Application**
- Detection: sql_injection_detection.spl (Searches 1-3)
- Data source: HTTP access logs (sourcetype=attack_sim:web)
- Simulator: web_attack_simulator.py
- Approach: Signature-based regex matching SQLi/XSS payloads in URL params, HTTP error rate anomaly, automated scanner user-agent detection.

### TA0002 — Execution

**T1059.007 — JavaScript Execution (XSS)**
- Detection: sql_injection_detection.spl (Search 1, XSS signatures)
- Data source: HTTP access logs
- Simulator: web_attack_simulator.py (XSS payloads)
- Approach: Pattern matching for script tags, event handlers (onerror, onload), javascript: URI schemes in decoded URLs.

### TA0006 — Credential Access

**T1110 — Brute Force**
- Detection: brute_force_detection.spl (Search 1)
- Data source: Auth logs (sshd, winlogon)
- Simulator: brute_force_simulator.py
- Approach: 10+ failures in 5-min window per source IP.

**T1110.001 — Password Guessing**
- Detection: brute_force_detection.spl (Search 1, auto-classified)
- Approach: Low unique-username count with high failure count = password guessing.

**T1110.003 — Password Spraying**
- Detection: brute_force_detection.spl (Search 3)
- Approach: 10+ unique usernames targeted from single source in 15 min.

### TA0004 — Privilege Escalation

**T1078 — Valid Accounts**
- Detection: privilege_escalation.spl (Search 1)
- Data source: Auth logs with privileged account activity
- Simulator: brute_force_simulator.py (successful logins to admin accounts)
- Approach: Privileged account logins from non-admin source IPs.

**T1078.001 — Default Accounts**
- Detection: privilege_escalation.spl (Search 1, username filter)
- Approach: Flags use of default account names (admin, root, guest).

**T1078.003 — Local Accounts**
- Detection: privilege_escalation.spl (Search 3)
- Approach: First-time access pattern for privileged local accounts.

### TA0008 — Lateral Movement

**T1021 — Remote Services**
- Detection: lateral_movement.spl (Search 1)
- Data source: Auth logs across multiple hosts
- Simulator: brute_force_simulator.py (multi-host successes)
- Approach: Single source authenticating to 3+ hosts in 30-min window.

**T1021.001 — Remote Desktop Protocol**
- Detection: lateral_movement.spl (Search 3, protocol=rdp filter)
- Approach: Non-admin workstation RDP access to server VLAN.

**T1021.002 — SMB/Windows Admin Shares**
- Detection: lateral_movement.spl (Search 3, protocol=smb filter)
- Approach: Workstation-to-server SMB connections from non-IT subnets.

### TA0011 — Command and Control

**T1071.001 — Web Protocols (HTTP C2)**
- Detection: Proxy log analysis for beaconing patterns
- Data source: Proxy/HTTP logs (sourcetype=attack_sim:proxy)
- Simulator: malware_callback_sim.py (protocol=http)
- Approach: Regular-interval HTTP POST to uncommon domains with encoded payloads.

**T1071.004 — DNS (DNS Tunneling C2)**
- Detection: data_exfiltration.spl (Search 4, subdomain length analysis)
- Data source: DNS query logs
- Simulator: malware_callback_sim.py (protocol=dns)
- Approach: Long hex-encoded subdomains, high query frequency to single domain.

**T1573.001 — Symmetric Encrypted Channel**
- Detection: Encrypted C2 over HTTPS with anomalous certificate/JA3 patterns
- Simulator: malware_callback_sim.py (HTTPS beacons)
- Note: Full JA3 fingerprinting requires Zeek/Suricata integration.

### TA0010 — Exfiltration

**T1048.001 — Exfiltration Over Encrypted Non-C2 Protocol**
- Detection: data_exfiltration.spl (Search 1, 3)
- Data source: NetFlow / proxy logs
- Simulator: data_exfil_simulator.py (protocol=https)
- Approach: Volume anomaly (transfers exceeding 5MB to external), off-hours timing.

**T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol**
- Detection: data_exfiltration.spl (Search 4)
- Data source: DNS query logs
- Simulator: data_exfil_simulator.py (protocol=dns)
- Approach: DNS tunneling via high-entropy long subdomain queries.

**T1567 — Exfiltration Over Web Service**
- Detection: data_exfiltration.spl (Search 2)
- Data source: Proxy/NetFlow logs
- Simulator: data_exfil_simulator.py (destinations include cloud storage, paste sites)
- Approach: Domain reputation matching against known file-sharing/paste services.

---

## ATT&CK Navigator Layer

To visualize this coverage in the MITRE ATT&CK Navigator:

1. Go to https://mitre-attack.github.io/attack-navigator/
2. Create new Enterprise layer
3. Search and highlight: T1190, T1059.007, T1110, T1110.001, T1110.003, T1078, T1078.001, T1078.003, T1021, T1021.001, T1021.002, T1071.001, T1071.004, T1573.001, T1048.001, T1048.003, T1567
4. Color code by detection confidence (green=high, yellow=medium)

---

## Future Coverage Expansion

| Priority | Technique | Description | Planned Project |
|----------|-----------|-------------|-----------------|
| High | T1059.001 | PowerShell Execution | Tier 3: EDR Simulation |
| High | T1055 | Process Injection | Tier 3: EDR Simulation |
| Medium | T1053 | Scheduled Task/Job | IR Framework (Tier 2) |
| Medium | T1003 | OS Credential Dumping | EDR Simulation (Tier 3) |
| Low | T1497 | Virtualization/Sandbox Evasion | Advanced detection lab |
