# IPv4 Addressing

**Module: 01-Networking-Fundamentals > IPv4-Addressing**  
*MSc Cybersecurity Portfolio — ATU Letterkenny*

Covers CIDR notation, IP classification, and VLSM subnetting as applied in the Enterprise Campus Network project.

---

## CIDR-Notation

CIDR (Classless Inter-Domain Routing) expresses IP addresses with their prefix length:

```
172.16.0.0/20    → 4,094 usable hosts
172.16.4.0/22    → 1,022 usable hosts
172.16.8.0/24    → 254 usable hosts
172.16.10.0/25   → 126 usable hosts
172.16.10.128/27 → 30 usable hosts
10.0.0.0/30      → 2 usable hosts (point-to-point WAN link)
```

**Formula:** Usable hosts = 2^(32-prefix) - 2

---

## IP-Classification

| Class | Range | Default Mask | Purpose |
|---|---|---|---|
| A | 1.0.0.0 – 126.255.255.255 | /8 | Large networks |
| B | 128.0.0.0 – 191.255.255.255 | /16 | Medium networks |
| C | 192.0.0.0 – 223.255.255.255 | /24 | Small networks |
| D | 224.0.0.0 – 239.255.255.255 | N/A | Multicast |
| E | 240.0.0.0 – 255.255.255.255 | N/A | Reserved |

**Private ranges (RFC 1918):**
```
10.0.0.0/8        → Class A private
172.16.0.0/12     → Class B private (our campus uses this)
192.168.0.0/16    → Class C private
```

---

## Subnetting-Exercises

### Campus Network VLSM Breakdown — 172.16.0.0/20

Starting with 172.16.0.0/20 (4,094 hosts), allocate sizes:

| Step | VLAN | Requirement | Subnet | Prefix | Hosts Available |
|---|---|---|---|---|---|
| 1 | Labs | 850 nodes | 172.16.0.0 | /22 | 1,022 |
| 2 | Students | 988 nodes | 172.16.4.0 | /22 | 1,022 |
| 3 | Staff | 200 nodes | 172.16.8.0 | /24 | 254 |
| 4 | Library | 200 nodes | 172.16.9.0 | /24 | 254 |
| 5 | Admin | 100 nodes | 172.16.10.0 | /25 | 126 |
| 6 | Finance | 20 nodes | 172.16.10.128 | /27 | 30 |
| 7 | Printers | 30 nodes | 172.16.10.160 | /27 | 30 |
| 8 | Servers | 30 nodes | 172.16.10.192 | /27 | 30 |
| 9 | Wireless | 250 nodes | 172.16.11.0 | /24 | 254 |
| 10 | CoLab | 130 nodes | 172.16.12.0 | /24 | 254 |
| 11 | Guest WiFi | 500 nodes | 172.16.14.0 | /23 | 510 |
| 12 | Management | 80 switches | 172.16.16.0 | /25 | 126 |
| 13 | WAN link | 2 routers | 10.0.0.0 | /30 | 2 |

**VLSM rule:** Always allocate the largest subnets first.

### Quick Subnet Reference

| Prefix | Hosts | Mask |
|---|---|---|
| /25 | 126 | 255.255.255.128 |
| /26 | 62 | 255.255.255.192 |
| /27 | 30 | 255.255.255.224 |
| /28 | 14 | 255.255.255.240 |
| /29 | 6 | 255.255.255.248 |
| /30 | 2 | 255.255.255.252 |

---

[← Campus Network Project](../Campus-Network-Design/README.md) | [← Back to Portfolio](../../README.md)
