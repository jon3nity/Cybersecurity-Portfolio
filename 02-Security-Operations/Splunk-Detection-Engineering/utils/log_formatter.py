"""
log_formatter.py — Multi-Format Log Serializer

Converts raw event dictionaries into industry-standard log formats for
Splunk ingestion. Supports syslog (RFC 5424), JSON, and CEF (ArcSight
Common Event Format).

Usage:
    from utils.log_formatter import LogFormatter
    
    formatter = LogFormatter(format_type="json")
    log_line = formatter.format(event_dict)
"""

import json
from datetime import datetime
from typing import Dict, Any


class LogFormatter:
    """
    Serialize event dictionaries into syslog, JSON, or CEF format.
    
    Each format is chosen to mirror what real Splunk deployments ingest:
    - syslog: Linux auth logs, firewalls, network devices
    - json:   Modern application logs, cloud services, APIs
    - cef:    ArcSight-compatible SIEM events (enterprise standard)
    """

    SUPPORTED_FORMATS = ("syslog", "json", "cef")

    def __init__(self, format_type: str = "json"):
        if format_type not in self.SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported format '{format_type}'. "
                f"Choose from: {self.SUPPORTED_FORMATS}"
            )
        self.format_type = format_type

    def format(self, event: Dict[str, Any]) -> str:
        """Route event to the correct formatter based on configured type."""
        formatter_map = {
            "syslog": self._to_syslog,
            "json":   self._to_json,
            "cef":    self._to_cef,
        }
        return formatter_map[self.format_type](event)

    # ── Syslog (RFC 5424-ish) ────────────────────────────────
    def _to_syslog(self, event: Dict[str, Any]) -> str:
        """
        Produce a syslog-style line:
        <priority>timestamp hostname process[pid]: message key=value ...
        
        Example output:
        <38>Feb 23 14:22:01 web-server-01 sshd[4821]: Failed password
        for admin from 185.220.101.42 port 22 action=failure
        """
        timestamp = event.get("timestamp", datetime.utcnow().strftime("%b %d %H:%M:%S"))
        hostname = event.get("hostname", "unknown-host")
        process = event.get("process", "security")
        pid = event.get("pid", 1000)
        message = event.get("message", "")
        severity = event.get("severity", 6)  # 6 = informational

        # Syslog priority = facility * 8 + severity (facility 4 = auth)
        priority = 4 * 8 + severity

        # Append extra fields as key=value pairs
        extras = " ".join(
            f'{k}="{v}"' if " " in str(v) else f"{k}={v}"
            for k, v in event.items()
            if k not in ("timestamp", "hostname", "process", "pid", "message", "severity")
        )

        return f"<{priority}>{timestamp} {hostname} {process}[{pid}]: {message} {extras}".strip()

    # ── JSON ─────────────────────────────────────────────────
    def _to_json(self, event: Dict[str, Any]) -> str:
        """
        Produce a single-line JSON object — the default for modern SIEM ingestion.
        Adds _time field for Splunk timestamp extraction.
        """
        # Ensure timestamp exists in ISO format for Splunk
        if "timestamp" not in event:
            event["timestamp"] = datetime.utcnow().isoformat() + "Z"
        event["_time"] = event["timestamp"]
        return json.dumps(event, default=str)

    # ── CEF (Common Event Format) ────────────────────────────
    def _to_cef(self, event: Dict[str, Any]) -> str:
        """
        ArcSight Common Event Format:
        CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
        
        Maps event fields to CEF extension keys (src, dst, act, msg, etc.)
        """
        vendor = "DetectionLab"
        product = "AttackSimulator"
        version = "1.0"
        sig_id = event.get("rule_id", "100")
        name = event.get("event_type", "SecurityEvent")
        severity = event.get("severity", 5)

        # Build CEF extension from remaining fields
        cef_key_map = {
            "src_ip": "src",
            "dst_ip": "dst",
            "src_port": "spt",
            "dst_port": "dpt",
            "username": "duser",
            "action": "act",
            "message": "msg",
            "protocol": "proto",
            "hostname": "dhost",
            "url": "request",
            "bytes_out": "out",
            "bytes_in": "in",
        }

        extensions = []
        for event_key, cef_key in cef_key_map.items():
            if event_key in event:
                extensions.append(f"{cef_key}={event[event_key]}")

        # Add timestamp
        ts = event.get("timestamp", datetime.utcnow().isoformat())
        extensions.append(f"rt={ts}")

        ext_str = " ".join(extensions)
        return f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name}|{severity}|{ext_str}"
