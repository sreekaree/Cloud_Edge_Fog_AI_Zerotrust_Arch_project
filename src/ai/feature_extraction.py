"""Transform real Phase 2 audit events into reproducible AI-ready features."""
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib

FEATURE_FIELDS = (
    "record_id", "timestamp_utc", "experiment_id", "source_device", "tenant_id", "source_ip",
    "destination", "destination_ip", "protocol", "service", "port", "packet_count",
    "flow_duration_ms", "flow_rate_pps", "connection_frequency_60s", "network_rtt_ms",
    "packet_loss_percent", "policy_decision_latency_ms", "decision", "trust_state",
    "enforcement", "scenario", "label", "label_basis",
)


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _label(scenario: str, labels: dict) -> tuple[str, str]:
    if scenario in labels["normal_scenarios"]: return "normal", "controlled_authorized_or_expected_request"
    if scenario in labels["anomalous_scenarios"]: return "anomalous", "controlled_policy_violation_or_restricted_state"
    raise ValueError(f"Scenario is not labeled in the pipeline configuration: {scenario}")


def extract_features(events: list[dict[str, str]], config: dict) -> list[dict]:
    """Extract observed features; absent measurements remain absent, never inferred."""
    window = float(config["pipeline"]["frequency_window_seconds"])
    packet_count = int(config["pipeline"]["packets_per_icmp_probe"])
    ordered = sorted(events, key=lambda event: event["timestamp_utc"])
    recent: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
    rows = []
    for event in ordered:
        timestamp = _timestamp(event["timestamp_utc"])
        key = (event["device_id"], event["destination_ip"])
        while recent[key] and (timestamp - recent[key][0]).total_seconds() > window: recent[key].popleft()
        frequency = len(recent[key]) + 1
        recent[key].append(timestamp)
        duration = float(event["total_request_latency_ms"])
        label, basis = _label(event["scenario"], config["labels"])
        stable = "|".join((event["timestamp_utc"], event["device_id"], event["destination_ip"], event["scenario"]))
        rows.append({
            "record_id": hashlib.sha256(stable.encode()).hexdigest()[:16], "timestamp_utc": event["timestamp_utc"],
            "experiment_id": event["scenario"], "source_device": event["device_id"], "tenant_id": event["tenant_id"],
            "source_ip": event["source_ip"], "destination": event["destination"], "destination_ip": event["destination_ip"],
            "protocol": "ICMP", "service": event["service"], "port": event["port"], "packet_count": packet_count,
            "flow_duration_ms": duration, "flow_rate_pps": round(packet_count / (duration / 1000), 6) if duration else None,
            "connection_frequency_60s": frequency, "network_rtt_ms": event["network_rtt_ms"] or None,
            "packet_loss_percent": event["packet_loss_percent"], "policy_decision_latency_ms": event["policy_decision_latency_ms"],
            "decision": event["decision"], "trust_state": event["trust_state"], "enforcement": event["enforcement"],
            "scenario": event["scenario"], "label": label, "label_basis": basis,
        })
    return rows
