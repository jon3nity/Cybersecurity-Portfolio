"""
splunk_hec_sender.py — Splunk HTTP Event Collector Client

Sends generated attack simulation events directly to a Splunk instance
via the HEC API endpoint. Supports batching for efficiency and automatic
retry on transient failures.

Usage:
    from utils.splunk_hec_sender import SplunkHECSender
    
    sender = SplunkHECSender(
        hec_url="https://localhost:8088",
        hec_token="your-token-here",
        index="attack_sim"
    )
    sender.send_event(event_dict, sourcetype="attack_sim:brute_force")
    sender.send_batch(list_of_events, sourcetype="attack_sim:web_attack")
"""

import json
import time
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkHECSender:
    """
    Client for Splunk's HTTP Event Collector (HEC).
    
    HEC is the standard method for programmatically sending data to Splunk.
    This client handles authentication, batching, and error handling so
    generator scripts can focus on producing realistic log data.
    """

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        index: str = "main",
        verify_ssl: bool = False,
        batch_size: int = 50,
        max_retries: int = 3,
    ):
        self.hec_url = hec_url.rstrip("/")
        self.endpoint = f"{self.hec_url}/services/collector/event"
        self.headers = {
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json",
        }
        self.index = index
        self.verify_ssl = verify_ssl
        self.batch_size = batch_size
        self.max_retries = max_retries

        # Tracking metrics
        self.events_sent = 0
        self.events_failed = 0

    def send_event(
        self,
        event: Dict[str, Any],
        sourcetype: str = "attack_sim",
        source: str = "detection_lab",
        host: Optional[str] = None,
    ) -> bool:
        """
        Send a single event to Splunk HEC.
        
        Args:
            event:      Dictionary containing the event data
            sourcetype: Splunk sourcetype for field extraction
            source:     Identifies the data origin
            host:       Override hostname (defaults to event's hostname field)
        
        Returns:
            True if the event was accepted by Splunk, False otherwise
        """
        payload = {
            "index": self.index,
            "sourcetype": sourcetype,
            "source": source,
            "host": host or event.get("hostname", "detection-lab"),
            "event": event,
        }

        # Use event timestamp if available
        if "timestamp" in event:
            try:
                dt = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                payload["time"] = dt.timestamp()
            except (ValueError, AttributeError):
                pass  # Let Splunk use ingestion time

        return self._post_with_retry(json.dumps(payload))

    def send_batch(
        self,
        events: List[Dict[str, Any]],
        sourcetype: str = "attack_sim",
        source: str = "detection_lab",
    ) -> Dict[str, int]:
        """
        Send multiple events in batched POST requests for efficiency.
        
        HEC accepts newline-delimited JSON payloads, which reduces
        HTTP overhead compared to one request per event.
        
        Returns:
            Dictionary with 'sent' and 'failed' counts
        """
        results = {"sent": 0, "failed": 0}

        for i in range(0, len(events), self.batch_size):
            batch = events[i : i + self.batch_size]
            payload_lines = []

            for event in batch:
                entry = {
                    "index": self.index,
                    "sourcetype": sourcetype,
                    "source": source,
                    "host": event.get("hostname", "detection-lab"),
                    "event": event,
                }
                payload_lines.append(json.dumps(entry))

            # HEC batch format: newline-separated JSON objects
            batch_payload = "\n".join(payload_lines)
            success = self._post_with_retry(batch_payload)

            if success:
                results["sent"] += len(batch)
            else:
                results["failed"] += len(batch)

        self.events_sent += results["sent"]
        self.events_failed += results["failed"]
        return results

    def _post_with_retry(self, payload: str) -> bool:
        """POST to HEC with exponential backoff retry on failure."""
        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.post(
                    self.endpoint,
                    headers=self.headers,
                    data=payload,
                    verify=self.verify_ssl,
                    timeout=10,
                )
                if response.status_code == 200:
                    return True
                elif response.status_code == 503:
                    # Splunk is busy — backoff and retry
                    wait = 2 ** attempt
                    print(f"  [HEC] Splunk busy, retrying in {wait}s (attempt {attempt})")
                    time.sleep(wait)
                else:
                    print(f"  [HEC] Error {response.status_code}: {response.text}")
                    return False
            except requests.exceptions.ConnectionError:
                if attempt < self.max_retries:
                    print(f"  [HEC] Connection failed, retrying... (attempt {attempt})")
                    time.sleep(2 ** attempt)
                else:
                    print("  [HEC] Connection failed after all retries")
                    return False
            except requests.exceptions.Timeout:
                print(f"  [HEC] Request timed out (attempt {attempt})")
                time.sleep(2)

        return False

    def get_stats(self) -> Dict[str, int]:
        """Return cumulative send statistics."""
        return {
            "events_sent": self.events_sent,
            "events_failed": self.events_failed,
            "total_attempted": self.events_sent + self.events_failed,
        }
