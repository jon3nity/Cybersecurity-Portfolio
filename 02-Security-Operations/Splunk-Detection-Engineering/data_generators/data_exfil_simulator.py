"""
data_exfil_simulator.py — Data Exfiltration Pattern Generator

Simulates insider threat and compromised host data exfiltration scenarios.
Generates network flow and proxy logs showing anomalous data transfers.

    MITRE ATT&CK:
    - T1048.001 — Exfiltration Over Symmetric Encrypted Non-C2 Protocol
    - T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol
    - T1567     — Exfiltration Over Web Service

Patterns generated:
    1. Large HTTP/HTTPS uploads to external destinations
    2. DNS tunneling exfiltration (high-volume DNS TXT queries)
    3. Off-hours data transfers (nights/weekends)
    4. Transfers to cloud storage (pastebin, file-sharing sites)
    5. Unusually large email attachments (SMTP)

Detection approach:
    Baseline normal transfer volumes, flag statistical outliers.
    Correlate with time-of-day and destination reputation.

Usage:
    python data_exfil_simulator.py --events 150 --protocol dns
    python data_exfil_simulator.py --events 300 --protocol https --off-hours
"""

import sys
import random
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))
import config
from data_generators.base_generator import BaseGenerator


class DataExfilSimulator(BaseGenerator):
    """
    Generate data exfiltration indicators within normal network traffic.
    
    The challenge for detection: legitimate large transfers happen daily
    (backups, cloud sync, video calls). Exfiltration stands out via:
    - Destination reputation (unknown external IPs)
    - Transfer timing (3 AM on a Saturday)
    - Volume anomaly (10x normal for this host)
    - Protocol abuse (DNS with huge TXT records)
    """

    # Suspicious external destinations
    EXFIL_DESTINATIONS = [
        {"domain": "mega.nz",               "ip": "89.44.169.135",  "type": "cloud_storage"},
        {"domain": "paste.ee",               "ip": "188.166.15.193", "type": "paste_site"},
        {"domain": "transfer.sh",            "ip": "144.76.175.228", "type": "file_share"},
        {"domain": "temp-mail-storage.xyz",  "ip": "203.0.113.99",  "type": "disposable"},
        {"domain": "anon-upload.io",         "ip": "198.51.100.88", "type": "anonymous"},
    ]

    # Legitimate destinations for normal large transfers
    LEGIT_DESTINATIONS = [
        {"domain": "onedrive.live.com",      "ip": "13.107.42.11",  "type": "corporate_cloud"},
        {"domain": "drive.google.com",       "ip": "142.250.80.46", "type": "corporate_cloud"},
        {"domain": "s3.amazonaws.com",       "ip": "52.216.0.1",    "type": "backup"},
        {"domain": "backup.company.com",     "ip": "10.0.2.50",     "type": "internal_backup"},
        {"domain": "sharepoint.com",         "ip": "13.107.136.9",  "type": "corporate_cloud"},
    ]

    def __init__(self, protocol: str = "https", off_hours: bool = False, **kwargs):
        super().__init__(
            name="data_exfiltration",
            sourcetype="attack_sim:netflow",
            **kwargs,
        )
        self.protocol = protocol
        self.off_hours = off_hours

    def generate_malicious_event(self, timestamp: str) -> Dict[str, Any]:
        """
        Produce an anomalous data transfer event indicating exfiltration.
        
        Key indicators that make these detectable:
        - Transfer sizes 10-100x larger than baseline
        - Destinations are file-sharing / paste sites
        - Timing clustered during off-hours
        """
        host_name, host_info = random.choice(list(config.TARGET_HOSTS.items()))
        destination = random.choice(self.EXFIL_DESTINATIONS)

        # Exfil transfers are notably larger than normal
        bytes_out = random.randint(5_000_000, 500_000_000)  # 5MB–500MB
        bytes_in = random.randint(100, 5000)  # Small response

        # Optionally shift timestamp to off-hours (suspicious timing)
        if self.off_hours:
            timestamp = self._shift_to_off_hours(timestamp)

        # Duration proportional to data volume
        duration_seconds = bytes_out / random.randint(500_000, 5_000_000)

        return {
            "timestamp": timestamp,
            "event_type": "network_flow",
            "hostname": host_name,
            "src_ip": host_info["ip"],
            "dst_ip": destination["ip"],
            "dst_port": 443 if self.protocol == "https" else 53,
            "protocol": self.protocol,
            "domain": destination["domain"],
            "destination_type": destination["type"],
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "duration_seconds": round(duration_seconds, 1),
            "transfer_ratio": round(bytes_out / max(bytes_in, 1), 1),
            "severity": 2,  # High severity
            "mitre_technique": config.MITRE_TECHNIQUES["exfil_http"]["id"],
            "mitre_tactic": config.MITRE_TECHNIQUES["exfil_http"]["tactic"],
            "message": (
                f"Large data transfer: {host_info['ip']} → {destination['domain']} "
                f"({bytes_out / 1_000_000:.1f} MB out, {bytes_in / 1000:.1f} KB in)"
            ),
            "is_malicious": True,
        }

    def generate_benign_event(self, timestamp: str) -> Dict[str, Any]:
        """
        Normal network transfer — cloud sync, backups, web browsing.
        These represent the baseline that exfil detection must NOT flag.
        """
        host_name, host_info = random.choice(list(config.TARGET_HOSTS.items()))
        destination = random.choice(self.LEGIT_DESTINATIONS)

        # Normal transfers: 1KB–5MB (occasional larger backups)
        is_backup = random.random() < 0.05
        if is_backup:
            bytes_out = random.randint(10_000_000, 50_000_000)  # Backup: 10-50MB
        else:
            bytes_out = random.randint(1000, 5_000_000)  # Normal: 1KB-5MB

        bytes_in = random.randint(1000, 100_000)

        return {
            "timestamp": timestamp,
            "event_type": "network_flow",
            "hostname": host_name,
            "src_ip": host_info["ip"],
            "dst_ip": destination["ip"],
            "dst_port": 443,
            "protocol": "https",
            "domain": destination["domain"],
            "destination_type": destination["type"],
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "duration_seconds": round(bytes_out / random.randint(1_000_000, 10_000_000), 1),
            "transfer_ratio": round(bytes_out / max(bytes_in, 1), 1),
            "severity": 6,
            "message": (
                f"Normal transfer: {host_info['ip']} → {destination['domain']} "
                f"({bytes_out / 1000:.1f} KB)"
            ),
            "is_malicious": False,
        }

    @staticmethod
    def _shift_to_off_hours(timestamp: str) -> str:
        """Move an event timestamp to off-business-hours (22:00–05:00)."""
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", ""))
            off_hour = random.choice([22, 23, 0, 1, 2, 3, 4])
            dt = dt.replace(hour=off_hour, minute=random.randint(0, 59))
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            return timestamp


# ── CLI Entry Point ──────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Generate data exfiltration pattern logs"
    )
    parser.add_argument("--events", type=int, default=150)
    parser.add_argument("--protocol", choices=["https", "dns"], default="https")
    parser.add_argument("--off-hours", action="store_true",
                        help="Shift malicious events to off-business hours")
    parser.add_argument("--format", choices=["json", "syslog", "cef"], default="json")
    parser.add_argument("--time-span", type=int, default=24)
    args = parser.parse_args()

    simulator = DataExfilSimulator(
        protocol=args.protocol,
        off_hours=args.off_hours,
        event_count=args.events,
        log_format=args.format,
        time_span_hours=args.time_span,
    )
    simulator.run()


if __name__ == "__main__":
    main()
