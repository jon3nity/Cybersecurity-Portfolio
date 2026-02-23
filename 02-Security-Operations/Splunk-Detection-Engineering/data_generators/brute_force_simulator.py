"""
brute_force_simulator.py — Authentication Attack Log Generator

Simulates credential-based attacks against SSH, RDP, and web login services.
Generates realistic authentication failure patterns that map to:

    MITRE ATT&CK:
    - T1110.001 — Brute Force: Password Guessing
    - T1110.003 — Brute Force: Password Spraying

Attack patterns generated:
    1. Classic brute force: Many attempts from one IP against one account
    2. Password spraying: One password tested across many accounts
    3. Credential stuffing: Rotating IP + username combinations
    4. Successful login after failures (attacker breaks through)

Usage:
    python brute_force_simulator.py --events 500 --service ssh
    python brute_force_simulator.py --events 1000 --service rdp --format syslog
"""

import sys
import random
import argparse
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))
import config
from data_generators.base_generator import BaseGenerator


class BruteForceSimulator(BaseGenerator):
    """
    Generate authentication failure logs mimicking real brute-force attacks.
    
    Produces a mix of:
    - Normal successful logins (benign baseline)
    - Concentrated failure bursts from attacker IPs (malicious)
    - Occasional attacker success (compromise indicator)
    """

    # Realistic usernames attackers target
    TARGET_USERNAMES = [
        "admin", "root", "administrator", "sysadmin", "backup",
        "deploy", "jenkins", "service_account", "test", "guest",
        "operator", "support", "webadmin", "ftpuser", "devops",
    ]

    # Common passwords in brute-force dictionaries
    ATTACK_PASSWORDS = [
        "password", "123456", "admin123", "root", "letmein",
        "qwerty", "password1", "iloveyou", "welcome", "monkey",
        "P@ssw0rd", "Summer2025!", "Company123", "Welcome1",
    ]

    SERVICES = {
        "ssh":  {"port": 22,  "process": "sshd",    "protocol": "ssh"},
        "rdp":  {"port": 3389, "process": "winlogon", "protocol": "rdp"},
        "web":  {"port": 443, "process": "nginx",    "protocol": "https"},
        "ftp":  {"port": 21,  "process": "vsftpd",   "protocol": "ftp"},
    }

    LEGITIMATE_USERS = [
        "john.doe", "jane.smith", "mike.ops", "sarah.dev",
        "alex.admin", "pat.security", "chris.network",
    ]

    def __init__(self, service: str = "ssh", **kwargs):
        super().__init__(
            name="brute_force",
            sourcetype="attack_sim:auth",
            **kwargs,
        )
        self.service = self.SERVICES.get(service, self.SERVICES["ssh"])
        self.service_name = service

        # Track per-attacker state for realistic burst patterns
        self._attacker_state = {}

    def generate_malicious_event(self, timestamp: str) -> Dict[str, Any]:
        """
        Produce a failed (or occasionally successful) authentication event
        from a simulated attacker IP.
        
        Attack realism features:
        - Attackers concentrate on specific target hosts
        - Failure streaks end with occasional success (1 in 50)
        - Source IPs rotate to simulate distributed attacks
        """
        attacker_ip = random.choice(config.EXTERNAL_ATTACKER_IPS)
        target = random.choice(list(config.TARGET_HOSTS.values()))
        username = random.choice(self.TARGET_USERNAMES)

        # 2% chance the attacker succeeds (realistic compromise)
        is_success = random.random() < 0.02
        action = "success" if is_success else "failure"
        severity = 2 if is_success else 4  # Critical if compromised

        # Choose attack sub-technique
        attack_pattern = random.choices(
            ["brute_force", "password_spray", "credential_stuff"],
            weights=[0.5, 0.3, 0.2],
        )[0]

        event = {
            "timestamp": timestamp,
            "event_type": "authentication",
            "hostname": [k for k, v in config.TARGET_HOSTS.items() if v == target][0],
            "src_ip": attacker_ip,
            "dst_ip": target["ip"],
            "dst_port": self.service["port"],
            "protocol": self.service["protocol"],
            "process": self.service["process"],
            "pid": random.randint(1000, 65535),
            "username": username,
            "action": action,
            "severity": severity,
            "attack_pattern": attack_pattern,
            "mitre_technique": config.MITRE_TECHNIQUES["brute_force"]["id"],
            "mitre_tactic": config.MITRE_TECHNIQUES["brute_force"]["tactic"],
            "message": self._build_message(action, username, attacker_ip),
            "is_malicious": True,
        }

        if is_success:
            event["alert_note"] = "POTENTIAL COMPROMISE — successful login after brute force"

        return event

    def generate_benign_event(self, timestamp: str) -> Dict[str, Any]:
        """
        Produce a normal successful authentication event from an internal IP.
        These form the baseline that detection rules must NOT alert on.
        """
        src_subnet = random.choice(config.INTERNAL_SUBNETS)
        src_ip = self._random_ip_from_subnet(src_subnet)
        target = random.choice(list(config.TARGET_HOSTS.values()))
        username = random.choice(self.LEGITIMATE_USERS)

        # Normal logins: 95% success, 5% typo/failure
        action = "success" if random.random() < 0.95 else "failure"

        return {
            "timestamp": timestamp,
            "event_type": "authentication",
            "hostname": [k for k, v in config.TARGET_HOSTS.items() if v == target][0],
            "src_ip": src_ip,
            "dst_ip": target["ip"],
            "dst_port": self.service["port"],
            "protocol": self.service["protocol"],
            "process": self.service["process"],
            "pid": random.randint(1000, 65535),
            "username": username,
            "action": action,
            "severity": 6,  # Informational
            "message": self._build_message(action, username, src_ip),
            "is_malicious": False,
        }

    def _build_message(self, action: str, username: str, src_ip: str) -> str:
        """Construct human-readable log message matching real sshd/auth format."""
        if action == "failure":
            return f"Failed password for {username} from {src_ip} port {self.service['port']}"
        return f"Accepted password for {username} from {src_ip} port {self.service['port']}"

    @staticmethod
    def _random_ip_from_subnet(subnet: str) -> str:
        """Generate a random IP within the given CIDR subnet."""
        base = subnet.split("/")[0]
        octets = base.split(".")
        octets[3] = str(random.randint(10, 254))
        return ".".join(octets)


# ── CLI Entry Point ──────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Generate brute-force authentication attack logs"
    )
    parser.add_argument("--events", type=int, default=500,
                        help="Number of events to generate (default: 500)")
    parser.add_argument("--service", choices=["ssh", "rdp", "web", "ftp"],
                        default="ssh", help="Target service (default: ssh)")
    parser.add_argument("--format", choices=["json", "syslog", "cef"],
                        default="json", help="Log output format (default: json)")
    parser.add_argument("--time-span", type=int, default=24,
                        help="Hours to spread events over (default: 24)")
    args = parser.parse_args()

    simulator = BruteForceSimulator(
        service=args.service,
        event_count=args.events,
        log_format=args.format,
        time_span_hours=args.time_span,
    )
    simulator.run()


if __name__ == "__main__":
    main()
