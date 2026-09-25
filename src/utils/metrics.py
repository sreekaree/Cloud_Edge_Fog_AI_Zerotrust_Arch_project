"""Machine-readable metrics output and aggregation."""
import csv
from pathlib import Path
from statistics import mean

FIELDS = ["timestamp_seconds", "packet_id", "source", "source_ip", "tenant", "device_type", "priority", "destination", "packet_count", "packet_size_bytes", "latency_ms", "throughput_mbps", "packet_loss"]


def write_csv(path: str | Path, rows: list[dict]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows: list[dict]) -> dict:
    received = [row for row in rows if row["packet_loss"] == 0]
    return {"packets": len(rows), "received": len(received), "mean_latency_ms": mean([row["latency_ms"] for row in received]) if received else 0.0,
            "mean_throughput_mbps": mean([row["throughput_mbps"] for row in received]) if received else 0.0,
            "loss_rate": 1 - len(received) / len(rows) if rows else 0.0}
