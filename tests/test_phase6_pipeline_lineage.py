"""MedTrustEdge Phase 6 — Pipeline Lineage and Baseline Provenance Tests.

Validates end-to-end lineage continuity across Phases 1-5, preservation of golden
baseline SHA-256 hashes, record ID alignment, trust state transition integrity,
and tamper sensitivity against unauthorized input mutations.
"""
from __future__ import annotations

import csv
import hashlib
from pathlib import Path
import unittest

from src.blockchain.event_adapter import EventAdapter, derive_record_id
from src.blockchain.ledger import BlockchainLedger
from src.blockchain.verifier import ChainVerifier

BASE_DIR = Path(__file__).resolve().parent.parent

# Golden baseline SHA-256 hashes for frozen Phase 1-4 artifacts
PROTECTED_HASHES: dict[str, str] = {
    "src/zerotrust/dynamic_trust.py": "5da36f2ca8d5a997d387a3ef325e3b0ce18ea38bcb45508d5c0e0ed909e8f519",
    "results/zerotrust/zerotrust_security_events.csv": "be661040b7eb0aba74a098195075c96af11d7fbc1319882a9b7fd7119ed5238b",
    "results/ai/phase3a_iomt_anomaly_dataset.csv": "284b1b5933c86f0fffd5a912a4ee3c2f019585b441c4b67097e04824d949cdd4",
    "results/ai/phase3b_predictions.csv": "f2fb282a417d3dbc53c31dde9260961fd4b6c3a7d425d55385023ebfb83a81e6",
    "results/phase4/phase4_trust_trace.csv": "c214728a41f7dacad9df105128b0a3ea686cf8be76646727fd12381c5c6e428d",
    "results/phase4/phase4_ablation_metrics.csv": "de5b7fbc0a16571f7dede132be2865f5c58c35bc3de01cbe74b112716474a809",
    "tests/test_phase4_dynamic_trust.py": "16894519e68dc5faf3da80779afb7f8f43bb4393ed3d484a4266d8a57cf8f581",
}

KEY_LINEAGE_ARTIFACTS: list[str] = [
    "results/fallback/baseline_comparison.csv",
    "results/zerotrust/zerotrust_security_events.csv",
    "results/ai/phase3a_iomt_anomaly_dataset.csv",
    "results/ai/phase3b_predictions.csv",
    "results/phase4/phase4_trust_trace.csv",
    "results/phase5/phase5_baseline_ledger.json",
]


class TestPhase6PipelineLineage(unittest.TestCase):
    """Lineage and baseline integrity test suite for Phase 6."""

    def test_lineage_artifacts_exist_and_non_empty(self):
        """Verifies that all representative Phase 1-5 artifacts exist and are non-empty."""
        for rel_path in KEY_LINEAGE_ARTIFACTS:
            path = BASE_DIR / rel_path
            self.assertTrue(path.exists(), f"Missing lineage artifact: {rel_path}")
            self.assertGreater(path.stat().st_size, 0, f"Empty lineage artifact: {rel_path}")

    def test_golden_baseline_hashes_protected(self):
        """Verifies that all 7 protected Phase 1-4 files match golden baseline SHA-256 digests."""
        for rel_path, expected_hash in PROTECTED_HASHES.items():
            path = BASE_DIR / rel_path
            self.assertTrue(path.exists(), f"Protected file missing: {rel_path}")
            raw_bytes = path.read_bytes()
            if rel_path.endswith(".py"):
                # Normalize CRLF -> LF on Windows for Python source files
                norm_bytes = raw_bytes.replace(b"\r\n", b"\n")
                computed_hash = hashlib.sha256(norm_bytes).hexdigest()
            else:
                computed_hash = hashlib.sha256(raw_bytes).hexdigest()

            self.assertEqual(
                computed_hash,
                expected_hash,
                f"Hash mismatch on protected file {rel_path}: expected {expected_hash}, got {computed_hash}",
            )

    def test_phase2_phase4_record_id_alignment(self):
        """Verifies record ID continuity between Phase 2 events and Phase 4 trust trace."""
        p2_path = BASE_DIR / "results" / "zerotrust" / "zerotrust_security_events.csv"
        p4_path = BASE_DIR / "results" / "phase4" / "phase4_trust_trace.csv"

        with open(p2_path, mode="r", encoding="utf-8") as f2:
            p2_rows = list(csv.DictReader(f2))
        with open(p4_path, mode="r", encoding="utf-8") as f4:
            p4_rows = list(csv.DictReader(f4))

        self.assertEqual(len(p2_rows), 25, "Phase 2 event count must be 25")
        self.assertEqual(len(p4_rows), 25, "Phase 4 trace count must be 25")

        p4_record_ids = [r["record_id"] for r in p4_rows]
        self.assertEqual(len(set(p4_record_ids)), 25, "Phase 4 record IDs must be distinct")

        # Verify deterministic record ID derivation from Phase 2 attributes
        for idx, (p2_row, p4_row) in enumerate(zip(p2_rows, p4_rows)):
            derived_id = derive_record_id(
                timestamp_utc=p2_row["timestamp_utc"],
                device_id=p2_row["device_id"],
                destination_ip=p2_row["destination_ip"],
                scenario=p2_row["scenario"],
            )
            self.assertEqual(
                p4_row["record_id"],
                derived_id,
                f"Record ID mismatch at row {idx}: Phase 4 {p4_row['record_id']} != derived {derived_id}",
            )

    def test_trust_state_transitions_preserved(self):
        """Verifies that dynamic trust states in Phase 4 trace contain valid transitions."""
        p4_path = BASE_DIR / "results" / "phase4" / "phase4_trust_trace.csv"
        valid_states = {"TRUSTED", "RESTRICTED", "REVOKED"}

        with open(p4_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            observed_states = set()
            transitions = []
            for row in reader:
                sb, sa = row["state_before"], row["state_after"]
                self.assertIn(sb, valid_states, f"Invalid state_before: {sb}")
                self.assertIn(sa, valid_states, f"Invalid state_after: {sa}")
                observed_states.add(sb)
                observed_states.add(sa)
                if sb != sa:
                    transitions.append((sb, sa))

        # Check that multiple distinct states exist and transitions occur
        self.assertGreaterEqual(len(observed_states), 2, "Must observe at least 2 distinct trust states")
        self.assertGreater(len(transitions), 0, "Must observe dynamic state transitions")

    def test_baseline_ledger_integrity_against_frozen_inputs(self):
        """Verifies that the blockchain ledger built from frozen inputs is 100% valid."""
        p4_path = BASE_DIR / "results" / "phase4" / "phase4_trust_trace.csv"
        p2_path = BASE_DIR / "results" / "zerotrust" / "zerotrust_security_events.csv"

        adapter = EventAdapter()
        events = adapter.adapt(p4_path, p2_path)
        self.assertEqual(len(events), 25)

        ledger = BlockchainLedger.build_from_events(events, batch_size=5)
        self.assertEqual(ledger.block_count, 6)
        self.assertEqual(ledger.total_event_count, 25)

        verifier = ChainVerifier()
        result = verifier.verify_ledger(ledger)
        self.assertTrue(result.is_valid, f"Verification failed with errors: {result.errors}")
        self.assertEqual(len(result.errors), 0)

    def test_negative_tampered_input_hash_detected(self):
        """Negative test: Mutating a single byte in an input payload alters its SHA-256 hash."""
        p4_path = BASE_DIR / "results" / "phase4" / "phase4_trust_trace.csv"
        raw_bytes = p4_path.read_bytes()
        expected_hash = PROTECTED_HASHES["results/phase4/phase4_trust_trace.csv"]

        # Mutate 1 byte
        tampered_bytes = bytearray(raw_bytes)
        tampered_bytes[0] = tampered_bytes[0] ^ 0xFF
        tampered_hash = hashlib.sha256(tampered_bytes).hexdigest()

        self.assertNotEqual(
            tampered_hash,
            expected_hash,
            "1-bit mutation must produce completely different SHA-256 digest (avalanche effect)",
        )


if __name__ == "__main__":
    unittest.main()
