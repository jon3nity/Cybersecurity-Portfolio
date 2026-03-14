# VLAN Security Implementation

**Module: 01-Networking-Fundamentals > VLAN-Security**  
*MSc Cybersecurity Portfolio — ATU Letterkenny*

This module covers VLAN creation, trunking, VTP architecture, inter-VLAN routing, and access port security hardening as implemented in the Enterprise Campus Network project.

**Implementation Order**
```
→ Configure VTP on all switches FIRST (before VLANs)
→ Create VLANs on MDF-SW (propagated by VTP where applicable)
→ Create relevant VLANs locally on each IDF (VTP Transparent)
→ Configure trunk ports on MDF-SW (Fa0/1–Fa0/9)
→ Configure trunk ports on all IDFs (uplink port)
→ Configure SVIs on MDF-SW (ip routing must be enabled first)
→ Configure WAN routed port (MDF-SW Fa0/10 → EDGE-RTR)
→ Configure access ports on all IDFs
→ Assign IP addresses and default gateways on all PCs
→ Assign management IPs (VLAN 99 SVI) on all IDF switches
→ SSH hardening on all switches
→ First ping test — verify inter-VLAN routing
→ CoLab trunk + config
→ EDGE-RTR config
→ OSPF/RIP routing
→ ACLs
```

---

## 1. VTP Configuration

> **Configure VTP before creating VLANs.** VTP domain and password must match on all switches before VLAN propagation works correctly.

**MDF-SW (VTP Server):**
```
enable
configure terminal
hostname MAIN-MDF-Switch
vtp mode server
vtp domain ATU-CAMPUS
vtp password jonATU123$ hidden
vtp version 2
enable secret jonATU123$
end
write memory
```

**Main Building IDFs — e.g. L1-IDF1 (VTP Transparent — prevents revision number attack):**
```
enable
configure terminal
hostname L1-IDF1
vtp mode transparent
vtp domain ATU-CAMPUS
vtp password jonATUL11 hidden
enable secret jonATUL11
end
write memory
```

> **Why Transparent and not Client?** A VTP Client accepts VLAN database updates from any switch with a higher revision number. A rogue switch plugged into any trunk port can silently overwrite all VLANs across the entire campus. Transparent mode forwards VTP advertisements without processing them — immune to revision number attacks. All 9 main building IDFs run Transparent.

**CoLab Switches (VTP Off — full administrative isolation):**
```
enable
configure terminal
vtp mode off
end
write memory
```

**Verify VTP:**
```
show vtp status
show vtp password
```

---

## 2. VLAN Creation

### On ATU-MDF-Switch — create ALL VLANs
```
enable
configure terminal

vlan 2
 name Labs
vlan 3
 name Students
vlan 4
 name Staff
vlan 5
 name Library
vlan 6
 name Admin
vlan 7
 name Finance
vlan 8
 name Wireless-APs
vlan 9
 name CoLab
vlan 10
 name Guest-Wifi
vlan 11
 name Printers
vlan 12
 name Servers
vlan 99
 name Management
exit

end
write memory
```

### On IDF switches — create ONLY VLANs relevant to that switch

> IDFs are VTP Transparent — they do not receive VTP updates from MDF-SW. Each IDF must have its local VLANs created manually. Only create VLANs that have active ports on that switch. VLAN 99 (Management) must be on every IDF.

**L1-IDF1 (Rm 1120) — Labs, Servers, Staff, Management:**
```
enable
configure terminal
vlan 2
 name Labs
vlan 4
 name Staff
vlan 12
 name Servers
vlan 99
 name Management
exit
end
write memory
```

**L1-IDF2 (Rm 1125) — Students, Staff, Admin, Management:**
```
enable
configure terminal
vlan 3
 name Students
vlan 4
 name Staff
vlan 6
 name Admin
vlan 99
 name Management
exit
end
write memory
```

**L1-IDF3 (Rm 1130) — Admin, Printers, Library, Management:**
```
enable
configure terminal
vlan 5
 name Library
vlan 6
 name Admin
vlan 10
 name Guest-Wifi
vlan 11
 name Printers
vlan 99
 name Management
exit
end
write memory
```
until .
.
.

**L3-IDF3 (Rm 3330) — Printers, Wireless-APs, Management:**
```
enable
configure terminal
vlan 8
 name Wireless-APs
vlan 11
 name Printers
vlan 99
 name Management
exit
end
write memory
```

**Verify VLANs on any switch:**
```
show vlan brief
```

---

## 3. Trunk Port Configuration

### Enable Layer 3 Routing on MDF-SW FIRST
```
enable
configure terminal
ip routing
```

> `ip routing` must be enabled before SVIs will route traffic. Without it, the 3560 operates as a pure Layer 2 switch even with SVIs configured.

### MDF-SW Trunk Ports — Cisco 3560 (Fa0/1 to Fa0/9)

> The 3560 supports both dot1q and ISL encapsulation. You **must** specify `switchport trunk encapsulation dot1q`.

> Apply least-privilege allowed VLAN lists per port - only carry VLANs needed by the switch at the other end. This limits broadcast scope and reduces VLAN hopping attack surface.

```
! Fa0/1 → L1-IDF1 (Rm 1120): Labs, Staff, Servers, Management
interface fastethernet 0/1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 2,4,12,99
 switchport nonegotiate
 no shutdown
exit

! Fa0/2 → L1-IDF2 (Rm 1125): Students, Staff, Admin, Management
interface fastethernet 0/2
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 3,4,6,99
 switchport nonegotiate
 no shutdown
exit

! Fa0/3 → L1-IDF3 (Rm 1130): Library, Admin, Guest-Wifi, Printers, Management
interface fastethernet 0/3
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 5,6,10,11,99
 switchport nonegotiate
 no shutdown
exit

! Fa0/4 → L2-IDF1 (Rm 2220): Library, Printers, Management
interface fastethernet 0/4
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 5,11,99
 switchport nonegotiate
 no shutdown
exit

! Fa0/5 → L2-IDF2 (Rm 2230): Students, Servers, Management
interface fastethernet 0/5
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 3,12,99
 switchport nonegotiate
 no shutdown
exit

! Fa0/6 → L2-IDF3 (Rm 2235): Staff, Finance, Wireless-APs, Management
interface fastethernet 0/6
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 4,7,8,99
 switchport nonegotiate
 no shutdown
exit

! Fa0/7 → L3-IDF1 (Rm 3320): Students, Staff, Management
interface fastethernet 0/7
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 3,4,99
 switchport nonegotiate
 no shutdown
exit

! Fa0/8 → L3-IDF2 (Rm 3325): Labs, Servers, Management
interface fastethernet 0/8
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 2,12,99
 switchport nonegotiate
 no shutdown
exit

! Fa0/9 → L3-IDF3 (Rm 3330): Printers, Wireless-APs, Management
interface fastethernet 0/9
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 8,11,99
 switchport nonegotiate
 no shutdown
exit

end
write memory
```

### IDF Trunk Ports — Cisco 2960 (uplink to MDF-SW)

> The 2960 only supports dot1q so the encapsulation command does not exist on it. Check with `show interfaces status` and configure whichever port shows `connected` toward MDF-SW.

```
! Run on each IDF — uplink port only (Fa0/1 or Gi0/1 depending on cable)
enable
configure terminal
interface fastethernet 0/1
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan [relevant VLANs for this switch],99
 switchport nonegotiate
 no shutdown
exit
end
write memory
```

**Verify trunks:**
```
show interfaces trunk
show interfaces fastethernet 0/1 switchport
```

---

## 4. SVI Configuration — MDF-SW

> One SVI per VLAN. The SVI IP address is the default gateway for all devices in that VLAN — same gateway regardless of which floor or IDF the device connects through.

```
enable
configure terminal

interface vlan 2
 ip address 172.16.0.1 255.255.252.0
 description Gateway-Labs
 no shutdown
exit
interface vlan 3
 ip address 172.16.4.1 255.255.252.0
 description Gateway-Students
 no shutdown
exit
interface vlan 4
 ip address 172.16.8.1 255.255.255.0
 description Gateway-Staff
 no shutdown
exit
interface vlan 5
 ip address 172.16.9.1 255.255.255.0
 description Gateway-Library
 no shutdown
exit
interface vlan 6
 ip address 172.16.10.1 255.255.255.128
 description Gateway-Admin
 no shutdown
exit
interface vlan 7
 ip address 172.16.10.129 255.255.255.224
 description Gateway-Finance
 no shutdown
exit
interface vlan 8
 ip address 172.16.11.1 255.255.255.0
 description Gateway-Wireless-APs
 no shutdown
exit
interface vlan 9
 ip address 172.16.12.1 255.255.255.0
 description Gateway-CoLab
 no shutdown
exit
interface vlan 10
 ip address 172.16.14.1 255.255.254.0
 description Gateway-Guest-WiFi
 no shutdown
exit
interface vlan 11
 ip address 172.16.10.161 255.255.255.224
 description Gateway-Printers
 no shutdown
exit
interface vlan 12
 ip address 172.16.10.193 255.255.255.224
 description Gateway-Servers
 no shutdown
exit
interface vlan 99
 ip address 172.16.16.1 255.255.255.128
 description Gateway-Management
 no shutdown
exit

end
write memory
```

**Verify SVIs — all should show UP/UP:**
```
show ip interface brief
```

> If an SVI shows `down/down` it means no active access ports are assigned to that VLAN yet. Configure access ports first then recheck. This is expected during build — not an error.

---

## 5. WAN Routed Port — MDF-SW Fa0/10 → EDGE-RTR

```
enable
configure terminal
interface fastethernet 0/10
 no switchport
 ip address 10.0.0.2 255.255.255.252
 description Link-to-EDGE-RTR
 no shutdown
exit

! Default route — all unknown traffic sent to edge router
ip route 0.0.0.0 0.0.0.0 10.0.0.1

end
write memory
```

**Edge Router (Router0) — matching config:**
```
enable
configure terminal
hostname EDGE-RTR
interface fastethernet 0/0
 ip address 10.0.0.1 255.255.255.252
 description Link-to-MDF-SW
 no shutdown
exit
end
write memory
```

> `/30` subnet used for WAN link — provides exactly 2 usable addresses (one per router end). VLSM principle: size every subnet to its actual requirement.

---

## 6. IDF Switch Management IPs

> Each IDF switch needs a VLAN 99 management IP so it can be reached via SSH from the admin workstation. The `ip default-gateway` command is required on Layer 2 switches (2960s) because they cannot route — without it, they can receive SSH connections from VLAN 99 only, not from other VLANs.

Example — L1-IDF1

```
enable
configure terminal
interface vlan 99
 ip address 172.16.16.2 255.255.255.128
 no shutdown
exit
ip default-gateway 172.16.16.1
end
write memory
```

| Switch | Management IP |
|---|---|
| MAIN-MDF-Switch | 172.16.16.1 (SVI — already set) |
| L1-IDF1 Rm 1120 | 172.16.16.2 |
| L1-IDF2 Rm 1125 | 172.16.16.3 |
| L1-IDF3 Rm 1130 | 172.16.16.4 |
| L2-IDF1 Rm 2220 | 172.16.16.5 |
| L2-IDF2 Rm 2230 | 172.16.16.6 |
| L2-IDF3 Rm 2235 | 172.16.16.7 |
| L3-IDF1 Rm 3320 | 172.16.16.8 |
| L3-IDF2 Rm 3325 | 172.16.16.9 |
| L3-IDF3 Rm 3330 | 172.16.16.10 |
| COLAB-CORE-SW | 172.16.16.12 |
| COLAB-L1 | 172.16.16.13 |
| COLAB-L2 | 172.16.16.14 |

---

## 7. Access Port Configuration — IDF Switches

```
! Example — assign ports to correct VLANs
interface fastethernet 0/2
 switchport mode access
 switchport access vlan 2
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
 no shutdown
exit

interface fastethernet 0/3
 switchport mode access
 switchport access vlan 4
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
 no shutdown
exit

! Shutdown ALL unused ports — assign to VLAN 99 (never VLAN 1)
interface range fastethernet 0/5 - 24
 switchport mode access
 switchport access vlan 99
 shutdown
exit
```

> **Why portfast on access ports?** When a PC connects, STP normally waits 30 seconds before forwarding (listening → learning → forwarding). Portfast skips this for end device ports, enabling instant connectivity. Never enable portfast on switch-to-switch links — it bypasses loop protection.

> **Why bpduguard?** If a switch is connected to a portfast port (intentionally or accidentally), it sends BPDUs. BPDUguard immediately err-disables the port on receiving any BPDU, shutting down the rogue switch connection automatically.

---

## 8. SSH Hardening — All Switches

```
enable
configure terminal
ip domain-name atu-campus.ie
username admin privilege 15 secret Cisco123!
crypto key generate rsa modulus 2048
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
line vty 0 15
 transport input ssh
 login local
 exec-timeout 5 0
exit
! Disable telnet on console too
line console 0
 exec-timeout 5 0
 login local
exit
end
write memory
```

> `transport input ssh` — critical line. Blocks all Telnet access. Without this, Telnet remains available as a fallback and all credentials are transmitted in cleartext across the network.

---

## Verify Security

```
show interfaces status
show mac address-table
show spanning-tree
show ssh
show running-config | include transport
show running-config | section line vty
show ip ssh
```

---

## End Device IP Reference

| VLAN | Device | IP | Mask | Gateway |
|---|---|---|---|---|
| 2 | Labs-L1 | 172.16.0.2 | 255.255.252.0 | 172.16.0.1 |
| 2 | Labs-L3 | 172.16.0.3 | 255.255.252.0 | 172.16.0.1 |
| 3 | Students-L1 | 172.16.4.2 | 255.255.252.0 | 172.16.4.1 |
| 3 | Students-L2 | 172.16.4.3 | 255.255.252.0 | 172.16.4.1 |
| 3 | Students-L3 | 172.16.4.4 | 255.255.252.0 | 172.16.4.1 |
| 4 | Staffs-L1 | 172.16.8.2 | 255.255.255.0 | 172.16.8.1 |
| 4 | Staff-L2 | 172.16.8.3 | 255.255.255.0 | 172.16.8.1 |
| 4 | Staff-L3 | 172.16.8.4 | 255.255.255.0 | 172.16.8.1 |
| 5 | Library-L1 | 172.16.9.2 | 255.255.255.0 | 172.16.9.1 |
| 5 | Library-L2 | 172.16.9.3 | 255.255.255.0 | 172.16.9.1 |
| 6 | ADMIN | 172.16.10.2 | 255.255.255.128 | 172.16.10.1 |
| 6 | Management-MAIN | 172.16.10.3 | 255.255.255.128 | 172.16.10.1 |
| 7 | Finance-Dept | 172.16.10.130 | 255.255.255.224 | 172.16.10.129 |
| 11 | Printer-L1 | 172.16.10.162 | 255.255.255.224 | 172.16.10.161 |
| 11 | Printer-L3 | 172.16.10.163 | 255.255.255.224 | 172.16.10.161 |
| 12 | Server-L1 | 172.16.10.194 | 255.255.255.224 | 172.16.10.193 |
| 12 | Server-L2 | 172.16.10.195 | 255.255.255.224 | 172.16.10.193 |
| 12 | Server-L3 | 172.16.10.196 | 255.255.255.224 | 172.16.10.193 |

> **Rule:** All devices in the same VLAN use the same gateway regardless of floor. Gateway = MDF-SW SVI for that VLAN. One VLAN = one subnet = one gateway.

---

## Key Design Decisions

**Why VTP Transparent on IDFs?**  
A VTP Client unconditionally accepts VLAN database updates from any switch with a higher revision number. A rogue switch connected to a trunk can silently overwrite all VLANs. Transparent mode forwards VTP advertisements without processing them, eliminating the revision number attack vector.

**Why native VLAN 99 on all trunks?**  
Untagged frames on a trunk are assigned to the native VLAN. VLAN 1 (default) is widely known and targeted in VLAN hopping attacks. Moving the native VLAN to 99, which carries no end user traffic, removes this attack surface entirely.

**Why nonegotiate on every port?**  
DTP allows an attacker to negotiate a trunk from an end device, gaining access to all VLANs on the switch. Disabling DTP with `switchport nonegotiate` on both access and trunk ports eliminates this VLAN hopping vector entirely.

**Why separate VLAN 6 (Admin users) from VLAN 99 (Management plane)?**  
Placing admin workstations directly in VLAN 99 gives end-user devices Layer 2 adjacency to all switch management interfaces. VLAN 6 creates a routing boundary — management traffic must pass through MDF-SW SVIs where ACLs can enforce additional access restrictions.

**Why per-port allowed VLAN lists on trunks?**  
Allowing all VLANs on every trunk (default behaviour) means a compromised device on one IDF can potentially receive broadcast traffic from VLANs it has no business seeing. Least-privilege VLAN lists on each trunk limit what traffic crosses each link.

---

[← Campus Network Project](../Campus-Network-Design/README.md) | [← Back to Portfolio](../../README.md)
