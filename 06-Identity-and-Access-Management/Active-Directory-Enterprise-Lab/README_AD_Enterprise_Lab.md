# Active Directory Enterprise Lab

**Identity & Infrastructure Project | MSc Cybersecurity Portfolio**
*Atlantic Technological University, Letterkenny | April 2026*

> This lab builds a three-phase enterprise Active Directory environment progressing from a local on-premises domain through Azure hybrid identity to Microsoft Sentinel SIEM monitoring. Each phase represents a distinct layer of real-world enterprise identity architecture that maps to [Enterprise Campus Network Design](/01-Networking-Fundamentals/).

---

## Lab Architecture

```
PHASE 1 — Local AD (Complete)
┌─────────────────────────────────────────────┐
│           VMware Workstation Player          │
│                                             │
│  DC01 (Windows Server 2022)                 │
│  ├── Domain: johnlab.local                  │
│  ├── ADDS + DNS + Global Catalog            │
│  ├── 7 OUs, 9 Users, 4 Security Groups      │
│  └── 3 GPOs (Password, Restrictions, Audit) │
│                          │                  │
│  CLIENT01 (Windows 10)   │                  │
│  ├── Domain joined        │                  │
│  ├── Auth via Kerberos ───┘                  │
│  └── GPO applied and verified               │
│                                             │
│  Network: 192.168.10.0/24 (Host-Only)       │
└─────────────────────────────────────────────┘

PHASE 2 — Azure Hybrid (Planned)
┌─────────────────────────────────────────────┐
│  Azure Entra ID (formerly Azure AD)         │
│  ├── Azure AD Connect sync from DC01        │
│  ├── Hybrid identity — same users in cloud  │
│  └── MFA enforcement via Conditional Access │
└─────────────────────────────────────────────┘

PHASE 3 — Sentinel SIEM (Planned)
┌─────────────────────────────────────────────┐
│  Microsoft Sentinel                         │
│  ├── Windows Security Event log ingestion   │
│  ├── Detection rules for Event IDs:         │
│  │   4625 (failed logon), 4740 (lockout)    │
│  │   4720 (account created), 4719 (tamper)  │
│  └── Incident response playbooks            │
└─────────────────────────────────────────────┘
```

---

## Network Context

This lab runs on an isolated Host-Only VMware network (192.168.10.0/24). In a production deployment, DC01 would reside in the **Servers VLAN (VLAN 12, 172.16.10.192/27)** of an enterprise campus network, accessible only from Admin VLAN (VLAN 6) and Management VLAN (VLAN 99) via inter-VLAN routing and ACL enforcement at the MDF core switch.

See: [Enterprise Campus Network Design](/01-Networking-Fundamentals/) for the network architecture this lab integrates with.

---

## Phase 1 — Local Active Directory Domain

![DC01 login screen showing JOHNLAB\Administrator](./Phase-1-Local-AD/screenshots/01_DC01_domain_login.png)
> **Figure 0:** DC01 login screen displaying JOHNLAB\Administrator: confirmation that the domain was successfully created and the server promoted to Domain Controller.

### VM Specifications

| VM | Role | OS | RAM | Disk | CPUs | IP |
|---|---|---|---|---|---|---|
| DC01 | Domain Controller | Windows Server 2022 | 4 GB | 40 GB | 2 | 192.168.10.1 |
| CLIENT01 | Domain Workstation | Windows 10 x64 | 4 GB | 30 GB | 2 | 192.168.10.10 |

### Domain Configuration

| Setting | Value |
|---|---|
| Domain Name | johnlab.local |
| NetBIOS Name | JOHNLAB |
| Forest Functional Level | Windows Server 2016 |
| DNS Server | DC01 (192.168.10.1) |
| DSRM | Configured (secured) |

### 1.2. OU Architecture

Designed to mirror the VLAN segmentation from the [Enterprise Campus Network Design](/01-Networking-Fundamentals/topology.png):

```
johnlab.local
└── ATU-Letterkenny
    ├── Staff              (maps to VLAN 4 — Staff)
    ├── Admin              (maps to VLAN 6 — Admin)
    ├── Finance            (maps to VLAN 7 — Finance)
    ├── IT-Labs            (maps to VLAN 2 — Labs)
    ├── Students           (maps to VLAN 3 — Students)
    ├── Servers            (maps to VLAN 12 — Servers)
    └── Service-Accounts   (cross-cutting — no direct VLAN)
```

![OU Structure — ATU-Letterkenny hierarchy in Active Directory Users and Computers](./Phase-1-Local-AD/screenshots/02_OU_structure.png)
> **Figure 1:** OU hierarchy under ATU-Letterkenny mirroring VLAN segmentation from the Enterprise Campus Network Design project.

### 1.3. Domain Users

| User | Username | OU | Security Group |
|---|---|---|---|
| Mary Murphy | mmurphy | Staff | Staff-Users |
| Patrick Kelly | pkelly | Staff | Staff-Users |
| Claire Byrne | cbyrne | Finance | Finance-Users |
| Seamus Walsh | swalsh | Finance | Finance-Users |
| Aoife O'Brien | aobrien | Admin | — |
| John Onyekachi | jonyekachi | IT-Labs | IT-Admins |
| Cian Ryan | cryan | Students | Students-Users |
| Niamh Gallagher | ngallagher | Students | Students-Users |
| svc_backup | svc_backup | Service-Accounts | — |

![Users distributed across OUs in Active Directory](./Phase-1-Local-AD/screenshots/03_users_in_OUs.png)
> **Figure 2:** Domain users for Students OUs. Each user's LDAP Distinguished Name reflects their OU placement, which determines GPO application.

### 1.4. Security Groups (AGDLP Pattern)

| Group | Type | Scope | Members |
|---|---|---|---|
| Finance-Users | Security | Global | cbyrne, swalsh |
| IT-Admins | Security | Global | jonyekachi |
| Staff-Users | Security | Global | mmurphy, pkelly |
| Students-Users | Security | Global | cryan, ngallagher |

### 1.5. Group Policy Objects

| GPO | Linked To | Key Settings |
|---|---|---|
| ATU-Password-Policy | johnlab.local | 12-char min, complexity, 90-day max, 10 history, 5-attempt lockout |
| ATU-Student-Restrictions | Students OU | Control Panel blocked, removable storage denied, software install blocked |
| ATU-Finance-Audit | Finance OU | 5 audit categories — generates Event IDs 4624, 4625, 4720, 4740, 4719 |

![GPMC showing all three GPOs linked to domain and OUs](./Phase-1-Local-AD/screenshots/04_GPO_overview.png)
> **Figure 3:** Group Policy Management Console showing ATU-Password-Policy linked at Domain level, ATU-Finance-Audit linked to Finance OU, & ATU-Student-Restrictions linked to Students OU.

![Password Policy GPO settings](./Phase-1-Local-AD/screenshots/05_password_policy.png)
> **Figure 4:** ATU-Password-Policy configured with 12-character minimum length, complexity enabled, 90-day maximum age, and 10-password history, aligned to NIST SP 800-63B.

![Finance Audit GPO settings](./Phase-1-Local-AD/screenshots/06_finance_audit.png)
> **Figure 5:** ATU-Finance-Audit policy showing five audit categories set to Success and Failure; generating Event IDs consumed by SIEM in Phase 3.

### Verification Evidence

```
C:\Users\jonyekachi> whoami
johnlab\jonyekachi

C:\Users\jonyekachi> echo %logonserver%
\\DC01

C:\Users\jonyekachi> gpresult /r
RSOP data for JOHNLAB\jonyekachi
Group Policy applied from: DC01.johnlab.local
CN=John Onyekachi,OU=IT-Labs,OU=ATU-Letterkenny,DC=johnlab,DC=local
```

![CLIENT01 login screen showing Sign in to JOHNLAB](./Phase-1-Local-AD/screenshots/08_client_domain_join.png)
> **Figure 6:** CLIENT01 login screen confirming successful domain join — "Sign in to: JOHNLAB" indicates Kerberos authentication is now handled by DC01.
---

![whoami logonserver gpresult verification output](./Phase-1-Local-AD/screenshots/07_domain_verification.png)
> **Figure 7:** Command-line verification confirming domain membership (johnlab\jonyekachi), authentication source (\\DC01), and LDAP Distinguished Name (CN=John Onyekachi,OU=IT-Labs,OU=ATU-Letterkenny,DC=johnlab,DC=local).

---

![GPO Student Restriction enforced on CLIENT01](./Phase-1-Local-AD/screenshots/09_GPO_student_restriction_enforced.png)
> **Figure 8:** ATU-Student-Restrictions GPO enforced live on CLIENT01 — Control Panel access blocked for domain user cryan (Students OU) with system restriction message. GPO configured on DC01 propagated and applied to workstation in real time, confirming end-to-end Group Policy enforcement.

---

## SOC Relevance — Event IDs Generated

The Finance Audit GPO generates the following Windows Security Event IDs, which feed directly into the Microsoft Sentinel workspace in Phase 3:

| Event ID | Description | Detection Use Case |
|---|---|---|
| 4624 | Successful logon | Baseline normal behaviour |
| 4625 | Failed logon | Brute force detection |
| 4720 | User account created | Rogue account creation alert |
| 4740 | Account locked out | Lockout storm detection |
| 4719 | Audit policy changed | GPO tamper detection |
| 4768 | Kerberos TGT requested | Kerberoasting baseline |
| 4769 | Kerberos service ticket | Pass-the-Ticket detection |

---

## MITRE ATT&CK Context | Attack Scenario Walkthrough — Phished Student Account

This lab environment is deliberately designed to understand the attacker's perspective on Active Directory:

**Scenario:** An attacker obtains `cryan`'s credentials through a phishing email and logs into CLIENT01 during off-hours.

**What the attacker encounters:**

The `ATU-Student-Restrictions` GPO immediately limits the attack surface. Control Panel is blocked — the attacker cannot change network settings, disable the firewall, or add local accounts. Removable storage is denied — USB-based data exfiltration is prevented. Software installation is blocked — the attacker cannot deploy malware, keyloggers, or command-and-control agents. The attacker is authenticated but operating inside a hardened, restricted environment.

**What DC01 sees — Event IDs generated:**

| Event ID | Description | Significance in this scenario |
|---|---|---|
| 4624 | Successful logon | cryan authenticates at 9:40pm — outside normal student hours, anomalous time |
| 4768 | Kerberos TGT requested | DC01 issues a ticket to cryan — source IP 192.168.10.10 expected, unexpected IP would alert |
| 4769 | Kerberos service ticket | Reveals which resources the attacker attempted to access after login |
| Object access | Finance resource access | If attacker reaches Finance share — Students OU user accessing Finance data is an immediate anomaly |

**The absence of Event ID 4740 is itself meaningful:**

No lockout events means the attacker had valid credentials from the start. This immediately rules out brute force and points toward phishing or credential theft — narrowing the investigation before a single log is manually reviewed. A SOC analyst seeing 4624 with no preceding 4625 failures, at an anomalous time, for a student account, is the detection signature for a successful phishing attack.

**The layered defence conclusion:**

No single control stopped the attack — the attacker authenticated successfully. But the combination of GPO restriction (limiting what they could do) and audit policy (generating the Event IDs that expose what they tried to do) is exactly how defence-in-depth operates in a real SOC environment. The GPO buys time; the audit trail enables response.
---

## Repository Structure

```
Active-Directory-Enterprise-Lab/
├── README.md                          ← This file
├── PROJECT_SUMMARY.md                 ← Portfolio summary (2-3 min read)
├── Phase-1-Local-AD/
│   ├── screenshots/                   ← Build evidence screenshots
│   ├── gpo-exports/                   ← Exported GPO backup files
│   └── verification/                  ← gpresult, whoami, ping outputs
├── Phase-2-Azure-Hybrid/              ← Planned
│   └── README.md
└── Phase-3-Sentinel-SIEM/             ← Planned
    └── README.md
```

---

## Implementation Status

| Phase | Description | Status |
|---|---|---|
| 1a | VM provisioning, DC01 promotion, domain creation | Complete |
| 1b | OU structure, user accounts, security groups | Complete |
| 1c | GPO deployment and verification | Complete |
| 1d | CLIENT01 domain join and GPO confirmation | Complete |
| 2 | Azure Entra ID hybrid sync via AD Connect | Planned |
| 3 | Microsoft Sentinel SIEM integration | Planned — dissertation phase |

---

## Related Projects

- [Enterprise Campus Network Design](../Campus-Network-Design/) — network architecture this lab integrates with
- [Splunk SIEM Lab](../Splunk-SIEM/) — parallel SIEM platform experience
- [MSc Dissertation — n8n as SOAR](../Dissertation/) — automation layer to be built on this infrastructure

---

**References:**
Microsoft (2024). Active Directory Domain Services Overview. Microsoft Learn. Available at: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview

NIST (2020). Special Publication 800-63B: Digital Identity Guidelines. National Institute of Standards and Technology. Available at: https://pages.nist.gov/800-63-3/sp800-63b.html

MITRE (2024). ATT&CK Framework v14. MITRE Corporation. Available at: https://attack.mitre.org

Stanek, W.R. (2013). *Windows Server 2012 R2 Inside Out*. Microsoft Press.

[← Back to Portfolio](../../README.md) | [View Project Summary](./PROJECT_SUMMARY_AD_Lab_Phase1.md)
