"""Unit and integration tests for MedTrustEdge Phase 5 Event Adapter and SHA-256 Hashing."""
from datetime import datetime
import hashlib
from pathlib import Path
import unittest

from src.blockchain.event_adapter import (
    BlockchainAdapterError,
    DuplicatePolicy,
    DuplicateRecordError,
    EventAdapter,
    SCHEMA_VERSION,
    SchemaValidationError,
    TrustEvent,
    UnmatchedRecordError,
    compute_event_hash,
    derive_record_id,
    to_canonical_json,
)

BASE_DIR = Path(__file__).resolve().parent.parent
PHASE4_CSV = BASE_DIR / "results" / "phase4" / "phase4_trust_trace.csv"
PHASE2_CSV = BASE_DIR / "results" / "zerotrust" / "zerotrust_security_events.csv"


class TestPhase5EventAdapter(unittest.TestCase):
    """Test suite covering Phase 5 event adaptation, canonical serialization, and hashing."""

    def setUp(self):
        self.adapter = EventAdapter()
        self.sample_p4_row = {
            "event_index": "0",
            "record_id": "fe9d845eac4fcde3",
            "source_device": "iotA1",
            "scenario": "authorized_edge",
            "p2_decision": "ALLOW",
            "p2_reason": "allowed",
            "jit_status": "Inactive",
            "severity": "NONE",
            "oof_score": "0.4399",
            "p_det": "0.0",
            "p_ai": "1.33",
            "p_total": "1.33",
            "rec": "0.0",
            "trust_before": "100.0",
            "trust_after": "98.67",
            "state_before": "TRUSTED",
            "state_after": "TRUSTED",
            "mapped_phase2_state": "TRUSTED",
            "n_viol_before": "0",
            "n_viol_after": "0",
            "action_taken": "ALLOW",
        }
        self.sample_p2_event = {
            "record_id": "fe9d845eac4fcde3",
            "timestamp_utc": "2026-09-23T06:58:21.029815+00:00",
            "device_id": "iotA1",
            "scenario": "authorized_edge",
            "decision": "ALLOW",
            "destination_ip": "10.1.1.10",
        }

    def test_01_canonical_serialization_sorted_and_compact(self):
        """Canonical serialization must enforce sorted keys and compact separators without whitespace."""
        payload = {
            "zebra": 1,
            "apple": 2,
            "nested": {"beta": 20, "alpha": 10},
        }
        canonical_str = to_canonical_json(payload)
        expected_str = '{"apple":2,"nested":{"alpha":10,"beta":20},"zebra":1}'
        self.assertEqual(canonical_str, expected_str)

        # Confirm reversing input order yields identical string
        reversed_payload = {
            "nested": {"beta": 20, "alpha": 10},
            "zebra": 1,
            "apple": 2,
        }
        self.assertEqual(to_canonical_json(reversed_payload), expected_str)

    def test_02_deterministic_sha256_hash(self):
        """SHA-256 hash must be deterministic, 64 hex characters, and strictly omit the hash from payload."""
        event = self.adapter.adapt_single_record(self.sample_p4_row, self.sample_p2_event)
        hash1 = event.compute_hash()
        hash2 = event.compute_hash()
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)
        self.assertEqual(hash1.lower(), hash1)

        # Hash must NOT be inside the payload being hashed
        payload_dict = event.to_payload_dict()
        self.assertNotIn("event_hash", payload_dict)
        self.assertNotIn("hash", payload_dict)

        # Enveloped dict includes both hash and payload
        enveloped = event.to_enveloped_dict()
        self.assertIn("event_hash", enveloped)
        self.assertIn("payload", enveloped)
        self.assertEqual(enveloped["event_hash"], hash1)

    def test_03_field_mapping_fidelity_all_21_fields(self):
        """All 21 Phase 4 fields and authoritative UTC timestamp must be accurately preserved."""
        event = self.adapter.adapt_single_record(self.sample_p4_row, self.sample_p2_event)
        self.assertEqual(event.event_index, 0)
        self.assertEqual(event.record_id, "fe9d845eac4fcde3")
        self.assertEqual(event.timestamp_utc, "2026-09-23T06:58:21.029815+00:00")
        self.assertEqual(event.source_device, "iotA1")
        self.assertEqual(event.scenario, "authorized_edge")
        self.assertEqual(event.p2_decision, "ALLOW")
        self.assertEqual(event.p2_reason, "allowed")
        self.assertEqual(event.jit_status, "Inactive")
        self.assertEqual(event.severity, "NONE")
        self.assertEqual(event.oof_score, 0.4399)
        self.assertEqual(event.p_det, 0.0)
        self.assertEqual(event.p_ai, 1.33)
        self.assertEqual(event.p_total, 1.33)
        self.assertEqual(event.rec, 0.0)
        self.assertEqual(event.trust_before, 100.0)
        self.assertEqual(event.trust_after, 98.67)
        self.assertEqual(event.state_before, "TRUSTED")
        self.assertEqual(event.state_after, "TRUSTED")
        self.assertEqual(event.mapped_phase2_state, "TRUSTED")
        self.assertEqual(event.n_viol_before, 0)
        self.assertEqual(event.n_viol_after, 0)
        self.assertEqual(event.action_taken, "ALLOW")
        self.assertEqual(event.schema_version, SCHEMA_VERSION)

    def test_04_timestamp_joining_verified_record_id(self):
        """Timestamps must join strictly on verified record_id, independent of row index."""
        events = self.adapter.adapt(PHASE4_CSV, PHASE2_CSV)
        self.assertEqual(len(events), 25)
        # Event 0: 2026-09-23T06:58:21.029815+00:00
        self.assertEqual(events[0].record_id, "fe9d845eac4fcde3")
        self.assertEqual(events[0].timestamp_utc, "2026-09-23T06:58:21.029815+00:00")
        # Event 24: 2026-09-23T07:00:49.015946+00:00
        self.assertEqual(events[24].record_id, "f9b31e9b94fdae42")
        self.assertEqual(events[24].timestamp_utc, "2026-09-23T07:00:49.015946+00:00")

    def test_05_unmatched_record_rejection(self):
        """Unmatched record_id in Phase 4 must raise UnmatchedRecordError, never fabricated."""
        bad_p4_row = dict(self.sample_p4_row)
        bad_p4_row["record_id"] = "unknown_rec_9999"
        p2_events = {"fe9d845eac4fcde3": self.sample_p2_event}

        with self.assertRaises(UnmatchedRecordError) as ctx:
            self.adapter.adapt([bad_p4_row], p2_events)
        self.assertIn("unknown_rec_9999", str(ctx.exception))

    def test_06_device_and_scenario_mismatch_rejection(self):
        """Mismatches between Phase 4 and Phase 2 device or scenario must raise SchemaValidationError."""
        # Device mismatch
        mismatched_p2 = dict(self.sample_p2_event, device_id="iotB1")
        with self.assertRaises(SchemaValidationError) as ctx:
            self.adapter.adapt_single_record(self.sample_p4_row, mismatched_p2)
        self.assertIn("Device mismatch", str(ctx.exception))

        # Scenario mismatch
        mismatched_p2_scen = dict(self.sample_p2_event, scenario="cross_tenant")
        with self.assertRaises(SchemaValidationError) as ctx:
            self.adapter.adapt_single_record(self.sample_p4_row, mismatched_p2_scen)
        self.assertIn("Scenario mismatch", str(ctx.exception))

    def test_07_duplicate_record_id_handling_policy(self):
        """Duplicate identifiers must be rejected under REJECT policy, and skipped under WARN_AND_SKIP."""
        dup_p4 = [self.sample_p4_row, self.sample_p4_row]
        p2_events = {self.sample_p4_row["record_id"]: self.sample_p2_event}

        # REJECT policy raises DuplicateRecordError
        strict_adapter = EventAdapter(duplicate_policy=DuplicatePolicy.REJECT)
        with self.assertRaises(DuplicateRecordError) as ctx:
            strict_adapter.adapt(dup_p4, p2_events)
        self.assertIn("Duplicate record_id", str(ctx.exception))

        # WARN_AND_SKIP policy skips duplicate
        lenient_adapter = EventAdapter(duplicate_policy=DuplicatePolicy.WARN_AND_SKIP)
        adapted = lenient_adapter.adapt(dup_p4, p2_events)
        self.assertEqual(len(adapted), 1)

    def test_08_optional_fields_and_metadata(self):
        """Optional metadata must be validated and included deterministically in payload."""
        event_with_meta = self.adapter.adapt_single_record(
            self.sample_p4_row,
            self.sample_p2_event,
            metadata={"hospital_node": "fogA", "tier": "fog"},
        )
        payload = event_with_meta.to_payload_dict()
        self.assertIn("metadata", payload)
        self.assertEqual(payload["metadata"]["hospital_node"], "fogA")

        # Invalid metadata type raises SchemaValidationError
        with self.assertRaises(SchemaValidationError):
            self.adapter.adapt_single_record(
                self.sample_p4_row,
                self.sample_p2_event,
                metadata="not-a-dict",  # type: ignore
            )

    def test_09_missing_required_fields_rejection(self):
        """Missing any required column from Phase 4 or Phase 2 must raise SchemaValidationError."""
        for field_name in ("event_index", "source_device", "trust_after", "p2_decision"):
            incomplete_row = dict(self.sample_p4_row)
            del incomplete_row[field_name]
            with self.assertRaises(SchemaValidationError):
                self.adapter.load_phase4_trace([incomplete_row])

    def test_10_invalid_numeric_and_boundary_values(self):
        """Out-of-boundary values must be rejected with SchemaValidationError."""
        # Negative event_index
        bad_idx = dict(self.sample_p4_row, event_index="-1")
        with self.assertRaises(SchemaValidationError):
            self.adapter.adapt_single_record(bad_idx, self.sample_p2_event)

        # oof_score > 1.0
        bad_oof = dict(self.sample_p4_row, oof_score="1.05")
        with self.assertRaises(SchemaValidationError):
            self.adapter.adapt_single_record(bad_oof, self.sample_p2_event)

        # trust_after < 0.0
        bad_trust = dict(self.sample_p4_row, trust_after="-5.0")
        with self.assertRaises(SchemaValidationError):
            self.adapter.adapt_single_record(bad_trust, self.sample_p2_event)

        # Invalid decision
        bad_dec = dict(self.sample_p4_row, p2_decision="SUSPEND")
        with self.assertRaises(SchemaValidationError):
            self.adapter.adapt_single_record(bad_dec, self.sample_p2_event)

        # Invalid state
        bad_state = dict(self.sample_p4_row, state_after="UNKNOWN_STATE")
        with self.assertRaises(SchemaValidationError):
            self.adapter.adapt_single_record(bad_state, self.sample_p2_event)

    def test_11_invalid_iso_timestamp_format(self):
        """Malformed timestamp string must raise SchemaValidationError."""
        bad_p2 = dict(self.sample_p2_event, timestamp_utc="not-a-valid-timestamp")
        with self.assertRaises(SchemaValidationError):
            self.adapter.adapt_single_record(self.sample_p4_row, bad_p2)

    def test_12_deterministic_event_ordering(self):
        """Events must be ordered chronologically by timestamp_utc with event_index as tie-breaker."""
        row0 = dict(self.sample_p4_row, event_index="0", record_id="rec0")
        row1 = dict(self.sample_p4_row, event_index="1", record_id="rec1")
        row2 = dict(self.sample_p4_row, event_index="2", record_id="rec2")

        p2_0 = dict(self.sample_p2_event, record_id="rec0", timestamp_utc="2026-09-23T06:58:21.000000+00:00")
        p2_1 = dict(self.sample_p2_event, record_id="rec1", timestamp_utc="2026-09-23T06:58:25.000000+00:00")
        p2_2 = dict(self.sample_p2_event, record_id="rec2", timestamp_utc="2026-09-23T06:58:25.000000+00:00")  # tie

        p2_events = {"rec0": p2_0, "rec1": p2_1, "rec2": p2_2}

        # Submit out of chronological order
        out_of_order = [row1, row2, row0]
        ordered = self.adapter.adapt(out_of_order, p2_events)

        self.assertEqual([e.event_index for e in ordered], [0, 1, 2])
        self.assertEqual([e.record_id for e in ordered], ["rec0", "rec1", "rec2"])

    def test_13_source_file_immutability(self):
        """Loading and adapting events must never alter or overwrite source Phase 1-4 CSV files."""
        with open(PHASE4_CSV, "rb") as fp:
            hash_p4_before = hashlib.sha256(fp.read()).hexdigest()
        with open(PHASE2_CSV, "rb") as fp:
            hash_p2_before = hashlib.sha256(fp.read()).hexdigest()

        # Run adaptation
        events = self.adapter.adapt(PHASE4_CSV, PHASE2_CSV)
        self.assertEqual(len(events), 25)

        with open(PHASE4_CSV, "rb") as fp:
            hash_p4_after = hashlib.sha256(fp.read()).hexdigest()
        with open(PHASE2_CSV, "rb") as fp:
            hash_p2_after = hashlib.sha256(fp.read()).hexdigest()

        self.assertEqual(hash_p4_before, hash_p4_after)
        self.assertEqual(hash_p2_before, hash_p2_after)

    def test_14_preservation_of_trust_scores_and_decisions(self):
        """Adapter must preserve exact trust scores and decisions without re-evaluating policies."""
        events = self.adapter.adapt(PHASE4_CSV, PHASE2_CSV)

        # Event 18: Cross-tenant denial
        ev18 = events[18]
        self.assertEqual(ev18.record_id, "6c905147705120e0")
        self.assertEqual(ev18.p2_decision, "DENY")
        self.assertEqual(ev18.p2_reason, "cross_tenant_denied")
        self.assertEqual(ev18.trust_before, 100.0)
        self.assertEqual(ev18.trust_after, 50.0)
        self.assertEqual(ev18.state_after, "RESTRICTED")

        # Event 20: Revoked state
        ev20 = events[20]
        self.assertEqual(ev20.record_id, "efe6e69631b35fc2")
        self.assertEqual(ev20.p2_decision, "DENY")
        self.assertEqual(ev20.trust_after, 0.0)
        self.assertEqual(ev20.state_after, "REVOKED")

        # Event 24: Post-JIT violation
        ev24 = events[24]
        self.assertEqual(ev24.record_id, "f9b31e9b94fdae42")
        self.assertEqual(ev24.p2_decision, "DENY")
        self.assertEqual(ev24.trust_after, 0.0)
        self.assertEqual(ev24.state_after, "REVOKED")

    def test_15_full_trace_real_data_roundtrip(self):
        """All 25 real project records must adapt cleanly with 0 rejected and 25 distinct hashes."""
        events = self.adapter.adapt(PHASE4_CSV, PHASE2_CSV)
        self.assertEqual(len(events), 25)

        hashes = [ev.event_hash for ev in events]
        self.assertEqual(len(set(hashes)), 25)
        for h in hashes:
            self.assertEqual(len(h), 64)


if __name__ == "__main__":
    unittest.main()
