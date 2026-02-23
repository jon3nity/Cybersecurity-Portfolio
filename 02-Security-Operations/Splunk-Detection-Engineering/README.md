# 🛡️ Splunk Detection Engineering Lab

> A production-grade SIEM detection engineering environment featuring realistic attack simulators, MITRE ATT&CK-mapped SPL detection rules, operational dashboards, alert configurations, and incident response playbooks.

**Author:** John Onyekachi | MSc Cybersecurity, ATU Letterkenny  
**Skills Demonstrated:** SIEM Engineering · Detection Rule Development · SPL · MITRE ATT&CK · Incident Response · Behavioral Analytics  
**Certifications:** Splunk Core Certified User · CompTIA Security+

---

## Table of Contents

- [Project Overview](#-project-overview)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Installation & Setup](#-installation--setup)
- [Usage Guide](#-usage-guide)
- [Data Generators](#-data-generators)
- [Detection Rules](#-detection-rules)
- [MITRE ATT&CK Coverage](#-mitre-attck-coverage)
- [Dashboards](#-dashboards)
- [Alert Configuration](#-alert-configuration)
- [Incident Response Playbooks](#-incident-response-playbooks)
- [Tuning & False Positive Reduction](#-tuning--false-positive-reduction)

---

## Project Overview

This lab simulates a real-world SOC detection engineering pipeline:

1. **Generate** → Python simulators create realistic attack log data (brute force, SQLi, C2 beaconing, data exfiltration)
2. **Ingest** → Logs feed into Splunk via monitor inputs or HEC
3. **Detect** → SPL correlation searches trigger on malicious patterns
4. **Alert** → Configurable alert thresholds with severity classification
5. **Respond** → Structured IR playbooks guide analyst response
6. **Map** → Every detection is mapped to MITRE ATT&CK techniques

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   ATTACK SIMULATION LAYER                │
│  brute_force  │  web_attack  │  malware_c2  │  exfil    │
└──────┬────────┴──────┬───────┴──────┬───────┴────┬──────┘
       │               │              │             │
       ▼               ▼              ▼             ▼
┌──────────────────────────────────────────────────────────┐
│              SPLUNK INGESTION (inputs.conf / HEC)        │
│              sourcetype = attack_sim:*                    │
└──────────────────────────┬───────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────┐
│              DETECTION ENGINE (SPL Searches)              │
│  Brute Force │ SQLi │ Priv Esc │ Lateral Mvmt │ Exfil   │
└──────────────────────────┬───────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────────┐
        │  ALERTS  │ │DASHBOARDS│ │IR PLAYBOOKS  │
        └──────────┘ └──────────┘ └──────────────┘
```


## Project Structure

```
Splunk-Detection-Engineering/
│
├── README.md                           
├── requirements.txt                    # Python dependencies
├── config.py                           # Global configuration
│
├── data-generators/                    # Attack log simulators
│   ├── __init__.py
│   ├── base_generator.py              # Abstract base class for all generators
│   ├── brute_force_simulator.py       # Authentication failure flood
│   ├── web_attack_simulator.py        # SQLi / XSS / path traversal
│   ├── malware_callback_sim.py        # C2 beaconing patterns
│   ├── data_exfil_simulator.py        # Large data transfer anomalies
│   └── run_all_generators.py          # Orchestrator to run all sims
│
├── detections/                         # SPL correlation searches
│   ├── brute_force_detection.spl      # T1110 - Credential brute force
│   ├── sql_injection_detection.spl    # T1190 - Exploit public-facing app
│   ├── privilege_escalation.spl       # T1078 - Valid account abuse
│   ├── lateral_movement.spl           # T1021 - Remote services
│   └── data_exfiltration.spl          # T1048 - Exfil over alt protocol
│
├── mitre-mapping/
│   └── attack_coverage.md             # Full ATT&CK technique mapping
│
├── dashboards/                         # Splunk XML dashboards
│   ├── threat_hunting_dashboard.xml   # Analyst deep-dive panel
│   ├── security_overview.xml          # Executive KPI dashboard
│   └── incident_timeline.xml          # Event timeline reconstruction
│
├── alerts/
│   ├── critical_alerts.conf           # savedsearches.conf entries
│   └── correlation_searches.conf      # Multi-event correlation rules
│
├── playbooks/                          # Incident response procedures
│   ├── brute_force_response.md        # IR playbook for credential attacks
│   └── malware_containment.md         # IR playbook for C2 / malware
│
└── utils/
    ├── __init__.py
    ├── log_formatter.py               # Syslog / JSON / CEF formatters
    └── splunk_hec_sender.py           # HTTP Event Collector client
```

---

## Installation & Setup

### Prerequisites

- Python 3.9+
- Splunk Enterprise (free trial) or Splunk Free
- Git

### Quick Start

```bash
# Clone the repository
git clone https://github.com/jon3nity/Cybersecurity-Portfolio.git
cd Cybersecurity-Portfolio/02-Security-Operations/Splunk-Detection-Engineering

# Create virtual environment
python -m venv venv
source venv/bin/activate   # Linux/Mac
# venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt

# Configure settings
cp config.py.example config.py
# Edit config.py with your Splunk HEC token and output paths

# Generate attack simulation logs
python data-generators/run_all_generators.py

# Import dashboards into Splunk via GUI or CLI
# Copy detections/*.spl into Splunk saved searches
```

### Splunk Configuration

1. **Create Index:** `splunk add index attack_sim`
2. **Ingest Data** *(choose one)*:
   - **Option A - HEC (recommended):** Run generators with `--hec` flag to push events directly to Splunk in real time
   - **Option B - Monitor Input:** Point Splunk at the `output/` directory to read generated log files from disk (`Settings → Data Inputs → Files & Directories`)
3. **Install Dashboards:** Settings → User Interface → Dashboards → Import XML
4. **Create Alerts:** Copy `alerts/critical_alerts.conf` entries into `$SPLUNK_HOME/etc/apps/search/local/savedsearches.conf`, or manually configure schedules via Settings → Searches, Reports, and Alerts

---

### Send Directly to Splunk HEC

```bash
# Using defaults from config.py (HEC URL + token pre-configured)
python data-generators/run_all_generators.py --all --hec

# Override HEC endpoint and token if needed
python data-generators/run_all_generators.py --all --hec --hec-url https://localhost:8088 --hec-token YOUR_TOKEN
```

## Usage Guide

### Generate Specific Attack Data

```bash
# Brute force only (500 events, targeting SSH)
python data-generators/brute_force_simulator.py --events 500 --service ssh

# Web attacks (SQL injection + XSS mix)
python data-generators/web_attack_simulator.py --events 300 --attack-types sqli,xss

# C2 beaconing (mimics Cobalt Strike intervals)
python data-generators/malware_callback_sim.py --events 200 --beacon-interval 60

# Data exfiltration (large DNS/HTTP transfers)
python data-generators/data_exfil_simulator.py --events 150 --protocol dns

# Run ALL simulators in sequence
python data-generators/run_all_generators.py --all
```

---

## Data Generators

| Simulator | Attack Type | MITRE ATT&CK | Log Format |
|-----------|-------------|---------------|------------|
| `brute_force_simulator.py` | Credential stuffing, password spray | T1110.001, T1110.003 | Syslog (auth) |
| `web_attack_simulator.py` | SQLi, XSS, path traversal, command injection | T1190, T1059.007 | Apache/Nginx access log |
| `malware_callback_sim.py` | C2 beaconing, DNS tunneling | T1071.001, T1071.004 | Proxy / DNS logs |
| `data_exfil_simulator.py` | Large transfers, off-hours exfil | T1048.001, T1048.003 | NetFlow / proxy logs |

Each generator produces realistic log entries with configurable volume, time spread, and mix of benign vs. malicious traffic for detection tuning.

---

## Detection Rules

| Rule | Technique | Severity | False Positive Rate |
|------|-----------|----------|---------------------|
| Brute Force Detection | T1110 | High | Low (tuned threshold) |
| SQL Injection Detection | T1190 | Critical | Medium (WAF noise) |
| Privilege Escalation | T1078 | Critical | Low |
| Lateral Movement | T1021 | High | Medium (admin noise) |
| Data Exfiltration | T1048 | Critical | Low (baseline required) |

---

## MITRE ATT&CK Coverage

Detections span **5 tactics** and **9 techniques** across the ATTACK framework. See [mitre-mapping/attack_coverage.md](mitre-mapping/attack_coverage.md) for the full matrix.

---

## Dashboards

- **Security Overview** - Executive-level KPIs: total alerts, severity distribution, trend lines
- **Threat Hunting** - Analyst drill-down: raw events, statistical outliers, field extraction
- **Incident Timeline** - Chronological event reconstruction for IR investigations

---

## Tuning & False Positive Reduction

Each detection rule includes inline tuning guidance:
- Threshold adjustment recommendations
- Whitelist patterns for known-good activity
- Statistical baselining approaches
- Alert fatigue reduction strategies

---

## License

This project is for educational and portfolio purposes never use against systems you don't own.
