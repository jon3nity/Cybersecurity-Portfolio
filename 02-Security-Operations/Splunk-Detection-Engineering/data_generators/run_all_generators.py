#!/usr/bin/env python3
"""
run_all_generators.py — Orchestrator for All Attack Simulators

Runs every generator in sequence (or selected ones) and optionally
pushes all events to Splunk HEC. This is the single entry point for
populating a Splunk instance with a full spectrum of attack data.

Usage:
    # Run all generators with default settings
    python run_all_generators.py --all

    # Run specific generators
    python run_all_generators.py --generators brute_force,web_attack

    # Run all and send to Splunk HEC
    python run_all_generators.py --all --hec \
        --hec-url https://localhost:8088 \
        --hec-token YOUR-TOKEN

    # Custom event counts
    python run_all_generators.py --all --events 1000
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
import config
from utils.splunk_hec_sender import SplunkHECSender

# Import all generators
from data_generators.brute_force_simulator import BruteForceSimulator
from data_generators.web_attack_simulator import WebAttackSimulator
from data_generators.malware_callback_sim import MalwareCallbackSimulator
from data_generators.data_exfil_simulator import DataExfilSimulator


# Registry of available generators with their default configs
GENERATORS = {
    "brute_force": {
        "class": BruteForceSimulator,
        "kwargs": {"service": "ssh"},
        "description": "Authentication brute force / password spray (T1110)",
    },
    "web_attack": {
        "class": WebAttackSimulator,
        "kwargs": {"attack_types": ["sqli", "xss", "path_traversal", "cmd_injection"]},
        "description": "SQL injection, XSS, path traversal, command injection (T1190)",
    },
    "malware_c2_http": {
        "class": MalwareCallbackSimulator,
        "kwargs": {"beacon_interval": 60, "jitter": 0.15, "protocol": "http"},
        "description": "HTTP C2 beaconing callbacks (T1071.001)",
    },
    "malware_c2_dns": {
        "class": MalwareCallbackSimulator,
        "kwargs": {"beacon_interval": 120, "jitter": 0.2, "protocol": "dns"},
        "description": "DNS tunneling C2 communication (T1071.004)",
    },
    "data_exfil": {
        "class": DataExfilSimulator,
        "kwargs": {"protocol": "https", "off_hours": True},
        "description": "Data exfiltration over HTTPS to external storage (T1048)",
    },
}


def run_generators(
    selected: list,
    event_count: int,
    log_format: str,
    time_span: int,
    hec_sender=None,
):
    """Execute selected generators and collect all events."""
    all_events = []
    start_time = datetime.utcnow()

    print("\n" + "=" * 70)
    print("  SPLUNK DETECTION ENGINEERING LAB — Attack Simulation Engine")
    print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Generators: {', '.join(selected)}")
    print(f"  Events per generator: {event_count}")
    print("=" * 70)

    for gen_name in selected:
        if gen_name not in GENERATORS:
            print(f"\n  [WARNING] Unknown generator: '{gen_name}' — skipping")
            continue

        gen_config = GENERATORS[gen_name]
        print(f"\n  → Running: {gen_config['description']}")

        # Instantiate generator with merged kwargs
        generator = gen_config["class"](
            event_count=event_count,
            log_format=log_format,
            time_span_hours=time_span,
            **gen_config["kwargs"],
        )

        events = generator.run(hec_sender=hec_sender)
        all_events.extend(events)

    # Final summary
    elapsed = (datetime.utcnow() - start_time).total_seconds()
    print("\n" + "=" * 70)
    print("  GENERATION COMPLETE")
    print(f"  Total events:   {len(all_events)}")
    print(f"  Output dir:     {config.LOG_DIR}")
    print(f"  Elapsed time:   {elapsed:.1f}s")
    if hec_sender:
        stats = hec_sender.get_stats()
        print(f"  HEC sent:       {stats['events_sent']}")
        print(f"  HEC failed:     {stats['events_failed']}")
    print("=" * 70)

    return all_events


def main():
    parser = argparse.ArgumentParser(
        description="Run attack simulation generators for Splunk Detection Engineering Lab"
    )
    parser.add_argument("--all", action="store_true",
                        help="Run all generators")
    parser.add_argument("--generators", type=str, default="",
                        help=f"Comma-separated list: {','.join(GENERATORS.keys())}")
    parser.add_argument("--events", type=int, default=config.DEFAULT_EVENT_COUNT,
                        help=f"Events per generator (default: {config.DEFAULT_EVENT_COUNT})")
    parser.add_argument("--format", choices=["json", "syslog", "cef"],
                        default=config.DEFAULT_LOG_FORMAT,
                        help="Log output format")
    parser.add_argument("--time-span", type=int, default=config.DEFAULT_TIME_SPAN_HOURS,
                        help="Hours to spread events over")

    # Splunk HEC options
    parser.add_argument("--hec", action="store_true",
                        help="Send events to Splunk HEC")
    parser.add_argument("--hec-url", type=str, default=config.SPLUNK_HEC_URL)
    parser.add_argument("--hec-token", type=str, default=config.SPLUNK_HEC_TOKEN)

    # List available generators
    parser.add_argument("--list", action="store_true",
                        help="List all available generators and exit")

    args = parser.parse_args()

    # List mode
    if args.list:
        print("\nAvailable generators:")
        for name, gen in GENERATORS.items():
            print(f"  {name:20s} — {gen['description']}")
        return

    # Determine which generators to run
    if args.all:
        selected = list(GENERATORS.keys())
    elif args.generators:
        selected = [g.strip() for g in args.generators.split(",")]
    else:
        parser.error("Specify --all or --generators=name1,name2")

    # Set up HEC sender if requested
    hec_sender = None
    if args.hec:
        hec_sender = SplunkHECSender(
            hec_url=args.hec_url,
            hec_token=args.hec_token,
            index=config.SPLUNK_INDEX,
        )
        print(f"\n  HEC endpoint: {args.hec_url}")

    run_generators(
        selected=selected,
        event_count=args.events,
        log_format=args.format,
        time_span=args.time_span,
        hec_sender=hec_sender,
    )


if __name__ == "__main__":
    main()
