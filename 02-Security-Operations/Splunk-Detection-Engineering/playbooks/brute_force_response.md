# Brute Force Incident Response Playbook

**Playbook ID:** IR-001  
**MITRE ATT&CK:** T1110 — Brute Force  
**Severity:** HIGH–CRITICAL  
**Last Updated:** February 2026  
**Author:** John Onyekachi, MSc Cybersecurity

---

## 1. Overview

This playbook guides SOC analysts through the investigation and response workflow when a brute-force alert triggers. It covers password guessing (T1110.001), password spraying (T1110.003), and credential stuffing attacks.

---

## 2. Alert Trigger Conditions

The following conditions activate this playbook:

- 10+ authentication failures from a single source IP in 5 minutes
- Password spraying: 10+ unique usernames targeted from one source in 15 minutes
- Compromise indicator: Successful login following a failure burst

---

## 3. Triage (First 15 Minutes)

### 3.1 Validate the Alert

1. Open the alert in Splunk and confirm the source IP, target host, and failure count
2. Check if the source IP is internal (misconfig/service account) or external (attack)
3. Verify the alert is not a known false positive (check whitelist lookup)

### 3.2 Classify Severity

| Condition | Severity | Escalation |
|-----------|----------|------------|
| External IP, failures only, no success | HIGH | SOC Tier 1 |
| External IP with successful login | CRITICAL | SOC Tier 2 + IR Lead |
| Internal IP spraying multiple accounts | CRITICAL | SOC Tier 2 + IT Admin |
| Known scanner IP (Qualys, Nessus) | LOW | Close as FP |

### 3.3 Initial SPL Queries

Run the following searches to scope the incident:

**Scope the attack window:**
```
index=attack_sim sourcetype="attack_sim:auth" src_ip="<ATTACKER_IP>"
| stats count BY action, username, hostname
| sort -count
```

**Check for successful compromise:**
```
index=attack_sim sourcetype="attack_sim:auth" src_ip="<ATTACKER_IP>" action="success"
| table _time, username, hostname, dst_ip
```

**Check if attacker moved laterally after compromise:**
```
index=attack_sim sourcetype="attack_sim:auth" action="success"
  src_ip IN (<COMPROMISED_HOST_IPs>)
| stats dc(dst_ip) AS targets BY src_ip, username
```

---

## 4. Containment (15–60 Minutes)

### 4.1 If No Successful Login (Attack Only)

1. Block the attacker IP at the perimeter firewall
2. Add IP to Splunk threat intelligence lookup for future correlation
3. Verify targeted accounts are not locked out (reset if needed)
4. No further containment required — proceed to documentation

### 4.2 If Successful Login Detected (Compromise)

**Immediate actions (within 15 minutes):**

1. Disable the compromised user account in Active Directory
2. Block the attacker IP at the perimeter firewall
3. Isolate the targeted host from the network if lateral movement is suspected
4. Force password reset for the compromised account

**Secondary actions (within 1 hour):**

5. Check for persistence mechanisms on the compromised host (scheduled tasks, new accounts, SSH keys)
6. Review all activity from the compromised account since the successful login
7. Check for data access or exfiltration from the compromised session
8. Scan the compromised host with EDR for malware indicators

---

## 5. Eradication

1. Remove any attacker-created accounts or SSH keys
2. Revoke any tokens or sessions associated with the compromised account
3. Remove any persistence mechanisms discovered during containment
4. Patch or harden the authentication service if a vulnerability was exploited

---

## 6. Recovery

1. Re-enable the user account with a new strong password
2. Enforce MFA on the affected account if not already enabled
3. Restore network connectivity to isolated hosts after verification
4. Monitor the previously compromised account for 72 hours with enhanced logging

---

## 7. Post-Incident

### 7.1 Detection Tuning

- Review alert thresholds: Was 10 failures in 5 minutes appropriate?
- Add any new false positive patterns to the whitelist
- Consider implementing account lockout policies if not in place
- Update the brute force detection rule if new attack patterns were observed

### 7.2 Documentation

Complete the incident report with:
- Timeline of events (first failure → last activity)
- Attacker IP(s) and any associated threat intelligence
- Compromised accounts and hosts
- Data potentially accessed
- Containment and remediation actions taken
- Lessons learned and recommendations

### 7.3 Metrics

Track for SOC reporting:
- Time to detect (alert trigger latency)
- Time to triage (alert → analyst assignment)
- Time to contain (triage → attacker blocked)
- Whether compromise occurred before detection

---

## 8. References

- MITRE ATT&CK T1110: https://attack.mitre.org/techniques/T1110/
- NIST SP 800-63B Digital Identity Guidelines (password policy)
- CIS Benchmark: Account Lockout Policy recommendations
