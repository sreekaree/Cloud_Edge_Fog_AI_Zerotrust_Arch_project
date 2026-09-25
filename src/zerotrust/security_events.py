"""Append-only local CSV and JSONL audit records (not blockchain)."""
import csv
import json
from pathlib import Path

FIELDS = ("timestamp_utc", "scenario", "device_id", "tenant_id", "source_ip", "destination", "destination_ip", "service", "port", "decision", "reason", "trust_state", "policy_id", "policy_decision_latency_ms", "network_rtt_ms", "total_request_latency_ms", "packet_loss_percent", "enforcement")


class SecurityEventLog:
    def __init__(self, results_dir: str | Path):
        self.results_dir = Path(results_dir); self.events = []

    def record(self, event: dict) -> None: self.events.append(event)

    def write(self) -> None:
        self.results_dir.mkdir(parents=True, exist_ok=True)
        for name in ("zerotrust_security_events.csv", "zerotrust_policy_decisions.csv"):
            with (self.results_dir / name).open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=FIELDS); writer.writeheader(); writer.writerows(self.events)
        with (self.results_dir / "zerotrust_security_events.jsonl").open("w", encoding="utf-8") as stream:
            for event in self.events: stream.write(json.dumps(event) + "\n")
