"""Dataset persistence and provenance for Phase 3A."""
import csv
import hashlib
import json
from pathlib import Path
from .feature_extraction import FEATURE_FIELDS


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_dataset(rows: list[dict], output_dir: str | Path, config: dict, source: Path) -> tuple[Path, Path, Path]:
    output_dir = Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
    dataset = output_dir / "phase3a_iomt_anomaly_dataset.csv"
    with dataset.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FEATURE_FIELDS); writer.writeheader(); writer.writerows(rows)
    schema = output_dir / "phase3a_feature_schema.json"
    schema.write_text(json.dumps({
        "dataset_version": config["pipeline"]["dataset_version"], "fields": list(FEATURE_FIELDS),
        "excluded_features": config["excluded_features"],
        "measurement_notes": {"packet_count": "Fixed 5-request ICMP probe used by the Phase 2 runner.", "network_rtt_ms": "Observed ping RTT; blank for enforced denied requests."},
    }, indent=2), encoding="utf-8")
    manifest = output_dir / "phase3a_manifest.json"
    counts = {label: sum(row["label"] == label for row in rows) for label in ("normal", "anomalous")}
    manifest.write_text(json.dumps({"source_file": str(source), "source_sha256": sha256(source), "records": len(rows), "label_counts": counts, "dataset_sha256": sha256(dataset)}, indent=2), encoding="utf-8")
    return dataset, schema, manifest
