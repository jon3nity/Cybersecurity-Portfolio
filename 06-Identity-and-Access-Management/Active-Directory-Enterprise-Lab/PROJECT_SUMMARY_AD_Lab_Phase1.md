# Active Directory Enterprise Lab — Phase 1: Local Domain Infrastructure

**Infrastructure & Identity Project | MSc Cybersecurity Portfolio**
*Atlantic Technological University, Letterkenny | April 2026*

> **Educational Context:** This project simulates a production enterprise identity environment using VMware Workstation Player and Windows Server 2022. All design decisions reflect real-world enterprise AD architecture aligned with the MITRE ATT&CK framework and Microsoft security baselines.

---

## Project Overview

**Objective:** Design, deploy, and document a fully operational Active Directory domain environment across two virtual machines, implementing enterprise-grade identity management, organisational structure, security group architecture, and Group Policy enforcement.

**Project Scale:**
- Two VMs: DC01 (Windows Server 2022 Domain Controller) and CLIENT01 (Windows 10 domain workstation)
- Domain: johnlab.local (NetBIOS: JOHNLAB) hosted on VMware Workstation Player
- OU hierarchy mirroring the VLAN segmentation from the ATU Letterkenny Campus Network Design project
- 9 domain users, 4 security groups, 3 Group Policy Objects across targeted OUs
- Full end-to-end verification: domain join, Kerberos authentication, GPO application confirmed

**Framework/Tools:** Microsoft Active Directory Domain Services, Group Policy Management Console, VMware Workstation Player, Windows Server 2022, Windows 10  
**Duration:** April 2026 (Phase 1 of 3) | **Output:** Operational AD domain with documented architecture, users, groups, and policies

---

## The Challenge

**Business Problem:**

Enterprise organisations depend on Active Directory as the single authoritative source of identity, authentication, and access control. Without a structured AD environment, user access is ungoverned, security policy cannot be enforced centrally, and audit trails for compliance and incident response are absent. For a SOC analyst, understanding how AD is constructed is a prerequisite for detecting when it is being attacked.

This lab replicates the identity infrastructure that underpins every mid-to-large enterprise in the Irish market. The Domain Controller is the highest-value target in any Active Directory environment — compromising it grants Domain Dominance, giving an attacker complete control over authentication, authorisation, and lateral movement across every domain-joined system (MITRE ATT&CK: Credential Access — Kerberoasting T1558.003, DCSync T1003.006; Lateral Movement — Pass the Hash T1550.002).

The design challenge was to build this environment correctly from first principles: proper DNS architecture, OU structure aligned to organisational function, least-privilege security group design, and GPO enforcement targeting specific user populations.

**Critical Design Requirements:**
- DC01 must use its own IP as DNS server — AD is entirely DNS-dependent for SRV record resolution
- OU structure must reflect real departmental segmentation to enable targeted GPO application
- Security groups must follow AGDLP pattern — accounts into Global groups, Global into Domain Local, permissions on Domain Local
- Audit policy must generate the specific Windows Event IDs monitored in SIEM platforms

---

## My Approach

### Four-Phase Implementation Methodology

**Phase 1: Infrastructure Provisioning**
- Created two VMware VMs: DC01 (4GB RAM, 40GB disk, 2 CPUs) and CLIENT01 (4GB RAM, 30GB disk, 2 CPUs)
- Configured Host-Only network adapter on both VMs — enforcing lab isolation with no external internet exposure
- Assigned static IP to DC01 (192.168.10.1/24) with DNS self-referencing (192.168.10.1) prior to AD promotion
- Assigned CLIENT01 static IP (192.168.10.10/24) with DNS pointed to DC01

**Phase 2: Domain Controller Promotion**
- Installed Active Directory Domain Services (ADDS) role via Server Manager
- Promoted DC01 to Domain Controller creating new forest: johnlab.local
- Configured DSRM password, DNS server role, and Global Catalog during promotion wizard
- Verified domain creation via JOHNLAB\Administrator login screen and dsa.msc console

**Phase 3: Identity Architecture Design**
- Designed OU hierarchy aligned to campus network VLAN structure (Staff/VLAN 4, Admin/VLAN 6, Finance/VLAN 7, IT-Labs/VLAN 2, Students/VLAN 3, Servers/VLAN 12, Service-Accounts)
- Created 9 domain user accounts distributed across correct OUs with standardised naming conventions
- Applied svc_ prefix convention to service account (svc_backup) for operational log clarity
- Created 4 Global Security Groups following AGDLP pattern: Finance-Users, IT-Admins, Staff-Users, Students-Users
- Added appropriate users as members of corresponding security groups

**Phase 4: Group Policy Enforcement**
- Deployed ATU-Password-Policy linked at domain level: 12-character minimum, complexity enabled, 90-day maximum age, 10-password history, 5-attempt lockout threshold, 30-minute lockout duration — aligned to NIST SP 800-63B
- Deployed ATU-Student-Restrictions linked to Students OU: Control Panel access blocked, removable storage denied, software installation prevented — User Configuration targeting
- Deployed ATU-Finance-Audit linked to Finance OU: five audit categories enabled (account logon, account management, logon events, object access, policy change) generating Event IDs 4624, 4625, 4720, 4740, 4719 — SIEM feed preparation for Phase 3

---

## Key Deliverables

### 1. Operational Active Directory Domain

**Fully promoted Domain Controller with verified authentication:**
- Domain: johnlab.local | NetBIOS: JOHNLAB | DC hostname: DC01
- FSMO roles held by DC01: PDC Emulator, RID Master, Infrastructure Master, Schema Master, Domain Naming Master
- Kerberos authentication verified: CLIENT01 login confirmed via `echo %logonserver%` returning \\DC01

### 2. OU Architecture Aligned to Network Segmentation

**Seven-OU hierarchy under ATU-Letterkenny mirroring campus VLAN design:**
- Each OU maps to a corresponding VLAN from the Enterprise Campus Network Design project
- Cross-project architectural coherence: network segmentation and identity segmentation follow the same organisational logic
- GPO targeting precision enabled by OU placement — Finance Audit applies only to Finance OU users

![OU hierarchy in Active Directory Users and Computers](./Phase-1-Local-AD/screenshots/02_OU_structure.png)
> **Figure 2:** ATU-Letterkenny OU structure with seven child OUs mirroring the VLAN architecture from the Campus Network Design project.

### 3. Security Group Structure

**Four Global Security Groups implementing AGDLP pattern:**
- Finance-Users: Claire Byrne, Seamus Walsh
- IT-Admins: John Onyekachi
- Staff-Users: Mary Murphy, Patrick Kelly
- Students-Users: Cian Ryan, Niamh Gallagher
- Service account svc_backup isolated in Service-Accounts OU with svc_ naming convention

### 4. Group Policy Objects

**Three targeted GPOs enforcing security baseline:**
- ATU-Password-Policy: domain-wide password and lockout controls per NIST SP 800-63B
- ATU-Student-Restrictions: User Configuration restrictions on Students OU — removable storage, Control Panel, software installation
- ATU-Finance-Audit: Computer Configuration audit policy on Finance OU generating five Event ID categories for SIEM ingestion

![GPMC showing three GPOs linked to domain and OUs](./Phase-1-Local-AD/screenshots/04_GPO_overview.png)
> **Figure 3:** Group Policy Management Console confirming all three GPOs correctly linked — Password Policy at domain level, Finance Audit and Student Restrictions at OU level.

### 5. Domain Join and GPO Verification

**CLIENT01 domain membership confirmed via command-line verification:**
- `whoami` returned: johnlab\jonyekachi
- `echo %logonserver%` returned: \\DC01
- `gpresult /r` confirmed: Group Policy applied from DC01.johnlab.local, LDAP path CN=John Onyekachi,OU=IT-Labs,OU=ATU-Letterkenny,DC=johnlab,DC=local

![Domain verification output — whoami, logonserver, gpresult](./Phase-1-Local-AD/screenshots/07_domain_verification.png)
> **Figure 1:** Command-line proof of domain membership, Kerberos authentication source, and GPO application from DC01.johnlab.local.

---

## Outcomes and Value

### Identity Infrastructure

**Results Achieved:**
- Fully operational enterprise domain with centralised authentication — zero local account dependency on CLIENT01
- Kerberos ticket-based authentication replacing password transmission on the network
- All 9 user identities managed centrally from DC01 — password resets, lockouts, and account management performed from single console

### Security Posture

**Before:** Two standalone VMs with local accounts and no centralised policy enforcement
**After:** Domain-joined environment with GPO-enforced password policy, targeted user restrictions, and Finance audit logging active
**Impact:** Every Finance user logon, file access, and policy change now generates auditable Windows Event Log entries consumable by a SIEM

### SOC Readiness

**Audit policy generates the following Event IDs for SIEM ingestion in Phase 3:**
- 4624 — Successful logon
- 4625 — Failed logon (lockout detection)
- 4720 — User account created
- 4740 — Account locked out
- 4719 — System audit policy changed (tamper detection)

### Architectural Coherence

**Cross-project integration achieved:**
- OU structure mirrors VLAN segmentation from Enterprise Campus Network Design
- Servers OU maps to VLAN 12 (172.16.10.192/27) — DC placement follows same isolation logic as network design
- README cross-references established between both portfolio projects

---

## Skills Demonstrated

**Active Directory Administration:**
- Domain Controller promotion from clean Windows Server installation
- OU design aligned to organisational and security requirements
- User, group, and service account provisioning with naming convention discipline
- AGDLP security group pattern implementation

**Group Policy Engineering:**
- GPO creation, linking, and scoping to domain and OU levels
- Password policy configuration per NIST SP 800-63B
- User Configuration vs Computer Configuration targeting decisions
- Audit policy configuration generating specific Windows Event IDs

**Infrastructure and Networking:**
- VMware Workstation VM provisioning and Host-Only network isolation
- Static IP assignment and DNS architecture for AD-dependent name resolution
- Cross-VM network troubleshooting (ping, IP configuration, firewall)

**Security Architecture Thinking:**
- Understanding DC as highest-value attack target (Domain Dominance concept)
- Mapping GPO audit settings to SIEM Event IDs — connecting configuration to detection
- Aligning identity segmentation to network segmentation for defence-in-depth

---

## Key Lessons Learned

**DNS is the foundation of Active Directory, not a supporting service:** Pointing DC01 DNS to 127.0.0.1 rather than its own IP caused CLIENT01 to fail domain join — the domain name johnlab.local could not be resolved. Correcting DNS to 192.168.10.1 immediately resolved the issue. In production, AD DNS failure is catastrophic and cascading.

**OU structure is a security enforcement boundary, not just an organisational label:** Linking GPOs to OUs means the organisational design directly determines which security policies apply to which users. Aligning OUs to network VLANs creates consistency between identity and network segmentation — reducing the cognitive load of security administration and improving auditability.

**GPO audit policy is the source, not the SIEM:** Configuring audit policy in Group Policy is what causes Windows to generate Event Log entries. Without the GPO, the events do not exist regardless of SIEM configuration. This connection between policy configuration and log generation is fundamental to SOC operations.

**Service account naming discipline matters at 3am:** When svc_backup authenticates at 3am, a SOC analyst immediately knows this is an automated process. When it authenticates from an unexpected workstation, the naming convention makes the anomaly obvious. Naming decisions made at provisioning time directly affect detection capability months later.

---

## Related Projects

[Enterprise Campus Network Design](../Campus-Network-Design/) • [Phase 2 — Azure Hybrid (Entra ID)](../AD-Enterprise-Lab/Phase-2/) • [Phase 3 — Microsoft Sentinel SIEM](../AD-Enterprise-Lab/Phase-3/)

---

**References:** Microsoft (2024). Active Directory Domain Services Overview. Microsoft Learn. | NIST (2020). SP 800-63B Digital Identity Guidelines. National Institute of Standards and Technology. | MITRE (2024). ATT&CK Framework — Credential Access. MITRE Corporation. | Stanek, W.R. (2013). Windows Server 2012 R2 Inside Out. Microsoft Press.

[← Back to Portfolio](../../README.md)
