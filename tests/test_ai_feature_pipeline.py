import csv
from pathlib import Path
import tempfile
import unittest
import yaml
from src.ai.dataset import write_dataset
from src.ai.feature_extraction import FEATURE_FIELDS, extract_features

ROOT = Path(__file__).resolve().parents[1]
CONFIG = yaml.safe_load((ROOT / "config" / "ai_feature_pipeline.yaml").read_text(encoding="utf-8"))


def event(timestamp, scenario, device="iotA1", destination="10.1.1.10"):
    return {"timestamp_utc": timestamp, "scenario": scenario, "device_id": device, "tenant_id": "A", "source_ip": "10.1.1.11", "destination": "edge_a", "destination_ip": destination, "service": "edge_telemetry", "port": "8443", "decision": "ALLOW", "reason": "allowed", "trust_state": "TRUSTED", "policy_id": "zt-healthcare-v1", "policy_decision_latency_ms": "0.02", "network_rtt_ms": "10.0", "total_request_latency_ms": "4000.0", "packet_loss_percent": "0", "enforcement": "none"}


class AiFeaturePipelineTests(unittest.TestCase):
    def test_extracts_only_observed_or_configured_features(self):
        rows = extract_features([event("2026-09-23T06:00:00+00:00", "authorized_edge"), event("2026-09-23T06:00:30+00:00", "cross_tenant")], CONFIG)
        self.assertEqual(len(rows), 2)
        self.assertEqual((rows[0]["protocol"], rows[0]["packet_count"], rows[0]["label"]), ("ICMP", 5, "normal"))
        self.assertEqual((rows[1]["connection_frequency_60s"], rows[1]["label"]), (2, "anomalous"))
        self.assertNotIn("bytes_transferred", rows[0])

    def test_dataset_has_stable_schema_and_manifest(self):
        rows = extract_features([event("2026-09-23T06:00:00+00:00", "authorized_edge")], CONFIG)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "events.csv"; source.write_text("event\nreal\n", encoding="utf-8")
            dataset, schema, manifest = write_dataset(rows, Path(directory) / "output", CONFIG, source)
            with dataset.open(newline="", encoding="utf-8") as stream: self.assertEqual(tuple(csv.DictReader(stream).fieldnames), FEATURE_FIELDS)
            self.assertTrue(schema.exists() and manifest.exists())
