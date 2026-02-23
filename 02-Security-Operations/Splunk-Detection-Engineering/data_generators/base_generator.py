"""
base_generator.py — Abstract Base Class for Attack Simulators

Provides the shared foundation for all data generators: timestamp
distribution, benign/malicious traffic mixing, file output, and
optional Splunk HEC forwarding. Subclasses implement the specific
attack logic by overriding `generate_malicious_event()` and
`generate_benign_event()`.

Design Pattern:
    Template Method — the `run()` method defines the generation
    algorithm while subclasses supply the event-specific behavior.
"""

import os
import sys
import json
import random
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add project root to path for config imports
sys.path.insert(0, str(Path(__file__).parent.parent))
import config
from utils.log_formatter import LogFormatter
from utils.splunk_hec_sender import SplunkHECSender


class BaseGenerator(ABC):
    """
    Template for all attack simulation generators.
    
    Handles the common workflow:
    1. Generate a mix of benign and malicious events
    2. Distribute timestamps realistically across a time window
    3. Write to file and/or send to Splunk HEC
    4. Print summary statistics
    """

    def __init__(
        self,
        name: str,
        sourcetype: str,
        event_count: int = config.DEFAULT_EVENT_COUNT,
        time_span_hours: int = config.DEFAULT_TIME_SPAN_HOURS,
        benign_ratio: float = config.BENIGN_TRAFFIC_RATIO,
        log_format: str = config.DEFAULT_LOG_FORMAT,
    ):
        self.name = name
        self.sourcetype = sourcetype
        self.event_count = event_count
        self.time_span_hours = time_span_hours
        self.benign_ratio = benign_ratio
        self.formatter = LogFormatter(format_type=log_format)

        # Output file path
        self.output_file = config.LOG_DIR / f"{self.name}.log"

        # Counters for summary
        self.malicious_count = 0
        self.benign_count = 0

    # ── Abstract methods subclasses MUST implement ───────────
    @abstractmethod
    def generate_malicious_event(self, timestamp: str) -> Dict[str, Any]:
        """Produce one malicious event dict with the given timestamp."""
        pass

    @abstractmethod
    def generate_benign_event(self, timestamp: str) -> Dict[str, Any]:
        """Produce one normal/benign event dict for realistic traffic mix."""
        pass

    # ── Timestamp distribution ───────────────────────────────
    def _generate_timestamps(self) -> List[str]:
        """
        Create a sorted list of realistic timestamps spread across
        the configured time window, with slight clustering to mimic
        real-world traffic patterns (more events during work hours).
        """
        now = datetime.utcnow()
        start = now - timedelta(hours=self.time_span_hours)
        timestamps = []

        for _ in range(self.event_count):
            # Weighted random offset — cluster toward recent hours
            offset_seconds = random.betavariate(2, 5) * self.time_span_hours * 3600
            event_time = start + timedelta(seconds=offset_seconds)
            timestamps.append(event_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))

        return sorted(timestamps)

    # ── Main execution pipeline ──────────────────────────────
    def run(
        self,
        hec_sender: Optional[SplunkHECSender] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate events, write to file, optionally send to HEC.
        
        Args:
            hec_sender: If provided, events are also sent to Splunk HEC
        
        Returns:
            List of all generated event dictionaries
        """
        print(f"\n{'='*60}")
        print(f"  {self.name} Generator")
        print(f"  Events: {self.event_count} | "
              f"Benign ratio: {self.benign_ratio:.0%} | "
              f"Time span: {self.time_span_hours}h")
        print(f"{'='*60}")

        timestamps = self._generate_timestamps()
        all_events = []

        for ts in timestamps:
            # Decide if this event is benign or malicious
            if random.random() < self.benign_ratio:
                event = self.generate_benign_event(ts)
                self.benign_count += 1
            else:
                event = self.generate_malicious_event(ts)
                self.malicious_count += 1

            all_events.append(event)

        # Write formatted logs to file
        self._write_to_file(all_events)

        # Optionally push to Splunk HEC
        if hec_sender:
            print(f"  Sending {len(all_events)} events to Splunk HEC...")
            results = hec_sender.send_batch(
                all_events, sourcetype=self.sourcetype
            )
            print(f"  HEC Results: {results['sent']} sent, {results['failed']} failed")

        # Print summary
        self._print_summary()
        return all_events

    def _write_to_file(self, events: List[Dict[str, Any]]) -> None:
        """Write all events to the output log file."""
        with open(self.output_file, "w") as f:
            for event in events:
                f.write(self.formatter.format(event) + "\n")
        print(f"  Output: {self.output_file}")

    def _print_summary(self) -> None:
        """Display generation statistics."""
        total = self.malicious_count + self.benign_count
        print(f"\n  Summary:")
        print(f"    Total events:     {total}")
        print(f"    Malicious events: {self.malicious_count} "
              f"({self.malicious_count / total:.1%})")
        print(f"    Benign events:    {self.benign_count} "
              f"({self.benign_count / total:.1%})")
        print(f"    File size:        {self.output_file.stat().st_size / 1024:.1f} KB")
