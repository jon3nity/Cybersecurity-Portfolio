# Enterprise Campus Network Design and Implementation

**Network Infrastructure Project | MSc Cybersecurity Portfolio**
*Atlantic Technological University, Letterkenny | March 2026*

> **Educational Context:** This project simulates an enterprise campus network for ATU Letterkenny using Cisco Packet Tracer. All device configurations, IP addressing, and security decisions reflect production-grade design principles.

---

## Project Overview

**Objective:** Design and implement a fully segmented, routed, and hardened enterprise campus network spanning two buildings, 13 VLANs, and over 2,300 addressable nodes using Cisco switching and routing infrastructure.

**Project Scale:**
- Two buildings: Main Building (3 floors, MDF + 9 IDF switches) and CoLab Building (3 switches)
- 13 VLANs covering Labs, Students, Staff, Library, Admin, Finance, Wireless, Servers, Printers, Management, and Guest Wi-Fi
- Base address space: 172.16.0.0/20, fully subnetted using VLSM
- Core switching: Cisco Catalyst 3560-24PS (Layer 3) as MDF; Cisco 2960s as IDF access switches
- Point-to-point WAN uplink: 10.0.0.0/30 between MDF and edge router

**Framework/Tools:** Cisco IOS CLI, Packet Tracer 8.x, VLSM subnetting, IEEE 802.1Q trunking, VTP, STP, OSPF/RIP  
**Duration:** March 2026 (ongoing) | **Output:** Fully operational simulated campus network with documentation

---

## The Challenge

**Business Problem:**

A university campus with two buildings, multiple departments, and over 2,300 users required a network architecture that enforced logical separation between user groups, maintained a dedicated management plane for infrastructure devices, and supported both wired and wireless connectivity — all while remaining scalable and administratively manageable.

Without proper segmentation, a flat network would expose Finance and Admin systems to student broadcast traffic, allow lateral movement between departments in a security incident, and make management of individual infrastructure devices unreliable. The design had to balance security, performance, and operational simplicity across a multi-floor, multi-building environment.

The project also required demonstrating enterprise-level decision-making: choosing VTP modes that eliminate revision number vulnerabilities, applying least-privilege trunk allowed VLAN lists, isolating the management plane from user VLANs, and hardening every access port against rogue device connection.

**Critical Requirements:**
- Complete Layer 2 isolation between departments via VLANs
- Layer 3 inter-VLAN routing centralised at the MDF core switch
- Dedicated out-of-band management plane (VLAN 99) with SSH-only access
- Wireless segmentation for staff (VLAN 8) and guest (VLAN 10) with planned ACL enforcement
- Zero reliance on VLAN 1 for any production or management traffic

---

## My Approach

### Six-Phase Implementation Methodology

**Phase 1: IP Addressing and VLAN Architecture Design**
- Applied VLSM to 172.16.0.0/20, allocating subnets sized precisely to each department's node count
- Designed 12 data VLANs plus VLAN 99 management, documented in a full subnetting reference table
- Selected /22 for Labs and Students (1,022 hosts each), /24 for Staff and CoLab, /27 for Finance, Servers, and Printers, /25 for Admin and Management
- Established a /30 point-to-point subnet (10.0.0.0/30) for the MDF-to-edge-router WAN link

**Phase 2: VTP Architecture and VLAN Propagation**
- Deployed hybrid VTP design: Server mode on MDF-SW, Transparent on all Main Building IDFs, Off on all CoLab switches
- Transparent mode on IDFs chosen specifically to eliminate VTP revision number vulnerability while retaining advertisement forwarding
- Configured VTP domain (ATU-CAMPUS) with MD5 password authentication to block rogue switch injection
- Created all 13 VLANs on MDF-SW; propagated automatically to VTP Client switches where applicable

**Phase 3: Trunk Configuration and SVI Deployment**
- Configured IEEE 802.1Q trunks on all MDF-SW uplink ports (Fa0/1-Fa0/9) with native VLAN 99 and per-port least-privilege allowed VLAN lists
- Applied `switchport nonegotiate` on every port to disable DTP and prevent rogue trunk establishment
- Configured all 13 SVIs on MDF-SW as inter-VLAN routing gateways; verified UP/UP status via `show ip interface brief`
- Enabled `ip routing` on the 3560 to activate Layer 3 forwarding between VLANs

**Phase 4: Access Port Configuration and End Device Addressing**
- Configured access ports on all 9 main building IDF switches with correct VLAN assignments, portfast, bpduguard, and nonegotiate
- Shut down all unused ports and assigned them to VLAN 99 to eliminate VLAN 1 exposure
- Assigned static IP addresses to all end devices using the VLSM table; verified single gateway per VLAN across all floors
- Diagnosed and resolved a critical SVI misconfiguration (typo: 72.16.4.1 instead of 172.16.4.1) using `show ip interface brief` verification discipline

**Phase 5: Management Plane and Switch Hardening**
- Assigned management IPs (172.16.16.x/25) to VLAN 99 SVIs on all IDF switches
- Configured `ip default-gateway 172.16.16.1` on all 2960 access switches for management reachability
- Implemented SSH v2 with RSA 2048-bit keys, local authentication, and `transport input ssh` on all VTY lines
- Applied exec-timeout, privilege level controls, and VTP password authentication across the management plane

**Phase 6: Verification and Connectivity Testing**
- Conducted systematic ping testing across all VLAN pairs to verify inter-VLAN routing
- Verified MAC address table population on IDF switches to confirm end device reachability
- Used `show interfaces trunk`, `show vlan brief`, and `show ip interface brief` as standard verification workflow after every configuration change
- Confirmed management PC (VLAN 6) can reach all switch management IPs (VLAN 99) via inter-VLAN routing through MDF-SW

---

## Key Deliverables

### 1. VLSM Subnetting Table

**Complete IP addressing scheme for 13 VLANs across 172.16.0.0/20:**
- Full subnet, mask, gateway, and usable range documented for every VLAN
- Switch management IPs allocated sequentially from 172.16.16.0/25 (MDF: .1, IDFs: .2-.14)
- Reference table used throughout implementation to eliminate addressing errors

### 2. Multi-Building Network Topology

**Hierarchical three-tier design across Main Building and CoLab:**
- Core: Cisco 3560-24PS (MDF-SW) — Layer 3 routing, all SVIs, VTP Server
- Distribution/Access: 9 x Cisco 2960 IDFs (Main Building), 3 x Cisco 2960 (CoLab)
- Physical topology follows Irish floor convention (Level 1 = Ground, Level 2 = 1st Floor MDF)
- Fibre risers connecting MDF to each floor IDF; dedicated trunk links throughout

### 3. VTP and Trunk Security Architecture

**Hybrid VTP deployment eliminating revision number attack surface:**
- MDF-SW: VTP Server — single authoritative VLAN source
- Main IDFs: VTP Transparent — local VLAN control, immune to revision number poisoning
- CoLab switches: VTP Off — full administrative isolation
- All trunks: per-port allowed VLAN lists (least privilege), native VLAN 99, DTP disabled

### 4. Inter-VLAN Routing Verification

**Confirmed cross-VLAN reachability across all tested pairs:**
- Labs (VLAN 2) to Staff (VLAN 4): successful
- Labs (VLAN 2) to Admin (VLAN 6): successful
- Labs (VLAN 2) to Students (VLAN 3): successful after SVI correction
- Management PC (VLAN 6) to Servers (VLAN 12): successful
- Management PC (VLAN 6) to switch management IPs (VLAN 99): successful

### 5. Access Port Security Hardening

**Per-port security applied to every end device connection:**
- Portfast enabled on all access ports (end devices only, never switch uplinks)
- BPDUGuard enabled — automatic err-disable on rogue switch connection
- Nonegotiate applied — DTP completely disabled network-wide
- Unused ports administratively shut down and assigned to VLAN 99

---

## Outcomes and Value

### Network Segmentation

**Results Achieved:**
- 13 isolated broadcast domains replacing a single flat network
- Finance (VLAN 7) and Admin (VLAN 6) traffic completely isolated from student VLANs at Layer 2
- Guest Wi-Fi (VLAN 10) separated from all internal VLANs; ACL enforcement planned for Phase 5

### Fault Diagnosis and Resolution

**Faults identified and resolved during implementation:**
- Duplicate management IP (172.16.16.5 assigned to two switches) — detected via ping conflict, resolved with `no ip address` correction
- SVI typo (72.16.4.1 vs 172.16.4.1) — detected via `show ip interface brief`, resolved immediately
- VTP revision number risk — mitigated by design choice of Transparent mode on all IDFs
- Incorrect gateway assignments (per-floor gateways instead of single VLAN gateway) — identified through MAC table analysis and corrected

### Management Plane Integrity

**Before:** No dedicated management plane — switches accessible only via console  
**After:** SSH-only remote access to all switches via VLAN 99 management IPs  
**Impact:** Full out-of-band management capability with encrypted access and authentication

### Security Posture

**Hardening measures deployed:**
- DTP disabled network-wide (nonegotiate on every port)
- VLAN 1 carries zero production or management traffic
- BPDUGuard provides automatic protection against rogue switch insertion
- VTP MD5 authentication prevents unauthorised VLAN database manipulation

---

## Skills Demonstrated

**Network Design and Architecture:**
- VLSM subnetting across a /20 address space for 13 VLANs
- Hierarchical campus network design (core/distribution/access)
- Multi-building topology planning with physical and logical separation

**Cisco IOS Configuration:**
- Layer 3 switching (SVI configuration, `ip routing`, routed ports)
- VTP modes, trunk configuration, native VLAN assignment
- Access port hardening (portfast, bpduguard, nonegotiate, port shutdown)
- SSH v2 hardening with RSA 2048-bit keys and VTY lockdown

**Troubleshooting and Verification:**
- Systematic use of `show ip interface brief`, `show interfaces trunk`, `show vlan brief`, `show mac address-table`
- Root cause analysis of connectivity failures through MAC table and switchport verification
- Typo detection and correction without service disruption

**Security Engineering:**
- Management plane separation (VLAN 99 isolated from user VLANs)
- Least-privilege trunk VLAN lists per interface
- Defence-in-depth approach to switch port security

---

## Key Lessons Learned

**Verify immediately after every configuration step:** A single digit typo in an SVI IP address (72.16.4.1 instead of 172.16.4.1) silently broke routing for an entire VLAN. Running `show ip interface brief` immediately after SVI configuration would have caught this in seconds rather than after extended troubleshooting. The discipline is: configure, verify, save, move on.

**VTP revision number vulnerability is a real enterprise risk:** Connecting a pre-configured switch with a higher VTP revision number to a production network can overwrite the entire VLAN database instantly. Setting all IDF switches to VTP Transparent mode eliminates this risk while still allowing VTP advertisement forwarding — a design decision that demonstrates enterprise-level security thinking.

**One VLAN equals one subnet equals one gateway:** Assigning different gateway IPs to devices in the same VLAN on different floors is a fundamental misconfiguration. The MDF-SW SVI is the single gateway for each VLAN regardless of which floor or IDF switch the device connects through. This principle, once understood, eliminates an entire category of routing failures.

**MAC address table analysis is a powerful diagnostic tool:** When ping fails, checking whether the destination device's MAC has been learned by the switch immediately distinguishes between a physical connectivity problem, a VLAN misconfiguration, and a routing issue. This approach is faster and more precise than repeated ping attempts.

---

## Related Projects

[Splunk SIEM Lab](../splunk-siem/) • [Cryptography Labs](../cryptography/) • [ISM2 Ransomware Governance](../ism2-ransomware/)

---

**References:** Cisco Systems (2024). Catalyst 2960 Series Switches Software Configuration Guide. Cisco Press. | Cisco Systems (2024). Catalyst 3560 Series Switches Software Configuration Guide. Cisco Press. | Teare, D. (2013). Implementing Cisco IP Routing (ROUTE) Foundation Learning Guide. Cisco Press. | Lammle, T. (2023). CompTIA Network+ Study Guide. Sybex.

[← Back to Portfolio](../../README.md)
