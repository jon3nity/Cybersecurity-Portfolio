"""
config.py — Global Configuration for Splunk Detection Engineering Lab

Centralizes all settings: output paths, Splunk HEC credentials, simulation
defaults, and network ranges. Edit this file to match your environment.
"""

import os
from pathlib import Path

# ─────────────────────────────────────────────
# PROJECT PATHS
# ─────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.resolve()
OUTPUT_DIR = PROJECT_ROOT / "output"
LOG_DIR = OUTPUT_DIR / "logs"

# Ensure output directories exist on import
OUTPUT_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────────
# SPLUNK HEC (HTTP Event Collector) SETTINGS
# ─────────────────────────────────────────────
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "YOUR-HEC-TOKEN-HERE")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "attack_sim")
SPLUNK_VERIFY_SSL = False  # Set True in production with valid certs

# ─────────────────────────────────────────────
# SIMULATION DEFAULTS
# ─────────────────────────────────────────────
DEFAULT_EVENT_COUNT = 500       # Events per generator run
DEFAULT_TIME_SPAN_HOURS = 24   # Spread events across this window
BENIGN_TRAFFIC_RATIO = 0.7     # 70% normal, 30% malicious (realistic mix)

# ─────────────────────────────────────────────
# NETWORK SIMULATION RANGES (RFC 1918)
# ─────────────────────────────────────────────
INTERNAL_SUBNETS = [
    "10.0.1.0/24",      # Corporate workstations
    "10.0.2.0/24",      # Server VLAN
    "10.0.3.0/24",      # DMZ
    "192.168.1.0/24",   # IT admin segment
]

EXTERNAL_ATTACKER_IPS = [
    "185.220.101.42",   # Known Tor exit node (simulated)
    "45.33.32.156",     # Simulated scanner
    "198.51.100.23",    # Simulated botnet controller
    "203.0.113.77",     # Simulated C2 server
    "91.121.87.45",     # Simulated brute-forcer
]

# ─────────────────────────────────────────────
# TARGET SERVICES & HOSTS
# ─────────────────────────────────────────────
TARGET_HOSTS = {
    "web-server-01":   {"ip": "10.0.3.10", "os": "Ubuntu 22.04", "services": ["http", "https"]},
    "db-server-01":    {"ip": "10.0.2.20", "os": "CentOS 8", "services": ["mysql", "ssh"]},
    "dc-01":           {"ip": "10.0.2.5",  "os": "Windows Server 2022", "services": ["ldap", "kerberos", "smb"]},
    "file-server-01":  {"ip": "10.0.2.30", "os": "Windows Server 2019", "services": ["smb", "rdp"]},
    "workstation-042": {"ip": "10.0.1.42", "os": "Windows 11", "services": ["rdp", "smb"]},
}

# ─────────────────────────────────────────────
# LOG FORMAT TEMPLATES
# ─────────────────────────────────────────────
SYSLOG_FACILITY = "auth"
LOG_FORMATS = ["syslog", "json", "cef"]  # Supported output formats
DEFAULT_LOG_FORMAT = "json"

# ─────────────────────────────────────────────
# MITRE ATT&CK TECHNIQUE REFERENCES
# ─────────────────────────────────────────────
MITRE_TECHNIQUES = {
    "brute_force":         {"id": "T1110",     "tactic": "Credential Access",    "name": "Brute Force"},
    "password_spraying":   {"id": "T1110.003", "tactic": "Credential Access",    "name": "Password Spraying"},
    "sql_injection":       {"id": "T1190",     "tactic": "Initial Access",       "name": "Exploit Public-Facing Application"},
    "xss":                 {"id": "T1059.007", "tactic": "Execution",            "name": "JavaScript Execution"},
    "privilege_escalation":{"id": "T1078",     "tactic": "Privilege Escalation",  "name": "Valid Accounts"},
    "lateral_movement":    {"id": "T1021",     "tactic": "Lateral Movement",     "name": "Remote Services"},
    "c2_http":             {"id": "T1071.001", "tactic": "Command and Control",  "name": "Web Protocols"},
    "c2_dns":              {"id": "T1071.004", "tactic": "Command and Control",  "name": "DNS"},
    "exfil_http":          {"id": "T1048.001", "tactic": "Exfiltration",         "name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol"},
    "exfil_dns":           {"id": "T1048.003", "tactic": "Exfiltration",         "name": "Exfiltration Over Unencrypted Non-C2 Protocol"},
}
