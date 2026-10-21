"""Automated Unit and Integration Tests for Phase 5 Tamper Detection and Verification."""
import copy
import json
from pathlib import Path
import unittest

from src.blockchain import (
    Block,
    BlockHeader,
    BlockchainLedger,
    ChainVerifier,
    EventAdapter,
    TrustEvent,
)
from experiments.run_phase5_tamper_experiments import (
    build_baseline_ledger,
    run_all_tamper_experiments,
)

BASE_DIR = Path(__file__).resolve().parent.parent
PHASE4_CSV = BASE_DIR / "results" / "phase4" / "phase4_trust_trace.csv"
PHASE2_CSV = BASE_DIR / "results" / "zerotrust" / "zerotrust_security_events.csv"
RESULTS_DIR = BASE_DIR / "results" / "phase5"


class TestPhase5TamperDetection(unittest.TestCase):
    """Test suite evaluating the 8 adversarial tampering scenarios and runner execution."""

    def setUp(self):
        self.adapter = EventAdapter()
        self.events = self.adapter.adapt(PHASE4_CSV, PHASE2_CSV)
        self.ledger = BlockchainLedger.build_from_events(self.events, batch_size=5)
        self.verifier = ChainVerifier()

    def test_01_baseline_ledger_integrity(self):
        """Untouched baseline ledger must pass all verification checks with zero errors."""
        res = self.verifier.verify_ledger(self.ledger)
        self.assertTrue(res.is_valid)
        self.assertEqual(len(res.errors), 0)
        self.assertEqual(res.block_count, 6)
        self.assertEqual(res.event_count, 25)

    def test_02_attack_A_modify_event_payload(self):
        """Attack A: Mutating payload without updating event hash must be detected as EVENT_PAYLOAD_TAMPERED."""
        copy_ledger = copy.deepcopy(self.ledger)
        b1 = copy_ledger.blocks[1]
        ev0 = b1.events[0]
        mutated_payload = ev0.to_payload_dict()
        mutated_payload["trust_after"] = 100.0  # altered score
        mutated_payload["recorded_hash"] = ev0.event_hash
        mutated_ev = TrustEvent(**mutated_payload)
        copy_ledger.blocks[1] = Block(header=b1.header, events=(mutated_ev,) + b1.events[1:])

        res = self.verifier.verify_ledger(copy_ledger)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.discrepancy_type, "EVENT_PAYLOAD_TAMPERED")
        self.assertEqual(res.tampered_block_index, 1)
        self.assertEqual(res.tampered_record_id, ev0.record_id)

        # Confirm original ledger untouched
        self.assertTrue(self.verifier.verify_ledger(self.ledger).is_valid)

    def test_03_attack_B_modify_stored_event_hash(self):
        """Attack B: Modifying stored event hash must be detected as EVENT_PAYLOAD_TAMPERED."""
        copy_ledger = copy.deepcopy(self.ledger)
        b2 = copy_ledger.blocks[2]
        ev1 = b2.events[1]
        mutated_payload = ev1.to_payload_dict()
        mutated_payload["recorded_hash"] = "0" * 64
        mutated_ev = TrustEvent(**mutated_payload)
        copy_ledger.blocks[2] = Block(header=b2.header, events=b2.events[:1] + (mutated_ev,) + b2.events[2:])

        res = self.verifier.verify_ledger(copy_ledger)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.discrepancy_type, "EVENT_PAYLOAD_TAMPERED")
        self.assertEqual(res.tampered_block_index, 2)
        self.assertEqual(res.tampered_record_id, ev1.record_id)
        self.assertTrue(self.verifier.verify_ledger(self.ledger).is_valid)

    def test_04_attack_C_modify_block_header_field(self):
        """Attack C: Modifying block header field must break linkage or header hash."""
        copy_ledger = copy.deepcopy(self.ledger)
        b2 = copy_ledger.blocks[2]
        new_header = BlockHeader(
            index=b2.index,
            previous_hash=b2.previous_hash,
            merkle_root=b2.merkle_root,
            timestamp_utc="2026-09-23T06:58:30.000000+00:00",
            difficulty=b2.header.difficulty,
            nonce=b2.header.nonce,
            schema_version=b2.header.schema_version,
        )
        copy_ledger.blocks[2] = Block(header=new_header, events=b2.events)

        res = self.verifier.verify_ledger(copy_ledger)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.discrepancy_type, "PREVIOUS_HASH_DISCONTINUITY")
        self.assertEqual(res.tampered_block_index, 3)
        self.assertTrue(self.verifier.verify_ledger(self.ledger).is_valid)

    def test_05_attack_D_break_previous_block_hash_link(self):
        """Attack D: Breaking previous_hash pointer must trigger PREVIOUS_HASH_DISCONTINUITY."""
        copy_ledger = copy.deepcopy(self.ledger)
        b4 = copy_ledger.blocks[4]
        new_header = BlockHeader(
            index=b4.index,
            previous_hash="f" * 64,
            merkle_root=b4.merkle_root,
            timestamp_utc=b4.timestamp_utc,
            difficulty=b4.header.difficulty,
            nonce=b4.header.nonce,
            schema_version=b4.header.schema_version,
        )
        copy_ledger.blocks[4] = Block(header=new_header, events=b4.events)

        res = self.verifier.verify_ledger(copy_ledger)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.discrepancy_type, "PREVIOUS_HASH_DISCONTINUITY")
        self.assertEqual(res.tampered_block_index, 4)
        self.assertTrue(self.verifier.verify_ledger(self.ledger).is_valid)

    def test_06_attack_E_reorder_events_within_block(self):
        """Attack E: Reordering events inside a block must violate chronological sequence or Merkle root."""
        copy_ledger = copy.deepcopy(self.ledger)
        b2 = copy_ledger.blocks[2]
        reordered = (b2.events[1], b2.events[0]) + b2.events[2:]
        copy_ledger.blocks[2] = Block(header=b2.header, events=reordered)

        res = self.verifier.verify_ledger(copy_ledger)
        self.assertFalse(res.is_valid)
        self.assertIn(res.discrepancy_type, ("CHRONOLOGICAL_REGRESSION", "MERKLE_ROOT_MISMATCH"))
        self.assertEqual(res.tampered_block_index, 2)
        self.assertTrue(self.verifier.verify_ledger(self.ledger).is_valid)

    def test_07_attack_F_reorder_blocks_in_chain(self):
        """Attack F: Swapping block positions must trigger INDEX_GAP."""
        copy_ledger = copy.deepcopy(self.ledger)
        copy_ledger.blocks[2], copy_ledger.blocks[3] = copy_ledger.blocks[3], copy_ledger.blocks[2]

        res = self.verifier.verify_ledger(copy_ledger)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.discrepancy_type, "INDEX_GAP")
        self.assertEqual(res.tampered_block_index, 2)
        self.assertTrue(self.verifier.verify_ledger(self.ledger).is_valid)

    def test_08_attack_G_delete_event_from_block(self):
        """Attack G: Deleting an event must trigger MERKLE_ROOT_MISMATCH."""
        copy_ledger = copy.deepcopy(self.ledger)
        b3 = copy_ledger.blocks[3]
        truncated = b3.events[:2] + b3.events[3:]
        copy_ledger.blocks[3] = Block(header=b3.header, events=truncated)

        res = self.verifier.verify_ledger(copy_ledger)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.discrepancy_type, "MERKLE_ROOT_MISMATCH")
        self.assertEqual(res.tampered_block_index, 3)
        self.assertTrue(self.verifier.verify_ledger(self.ledger).is_valid)

    def test_09_attack_H_delete_intermediate_block(self):
        """Attack H: Deleting an intermediate block must trigger INDEX_GAP."""
        copy_ledger = copy.deepcopy(self.ledger)
        del copy_ledger.blocks[3]

        res = self.verifier.verify_ledger(copy_ledger)
        self.assertFalse(res.is_valid)
        self.assertEqual(res.discrepancy_type, "INDEX_GAP")
        self.assertEqual(res.tampered_block_index, 3)
        self.assertTrue(self.verifier.verify_ledger(self.ledger).is_valid)

    def test_10_runner_produces_valid_reports(self):
        """Experiment runner must execute all 8 attacks and create valid CSV/JSON reports."""
        exps, summary = run_all_tamper_experiments(batch_size=5)
        self.assertEqual(len(exps), 8)
        self.assertEqual(summary["evaluation_summary"]["total_attacks_simulated"], 8)
        self.assertEqual(summary["evaluation_summary"]["total_attacks_detected"], 8)
        self.assertEqual(summary["evaluation_summary"]["detection_rate_percent"], 100.0)
        self.assertTrue(summary["evaluation_summary"]["original_ledger_consistent_throughout"])

        # Check output files exist
        csv_path = RESULTS_DIR / "phase5_tamper_detection_report.csv"
        json_path = RESULTS_DIR / "phase5_tamper_detection_summary.json"
        self.assertTrue(csv_path.is_file())
        self.assertTrue(json_path.is_file())

        with open(json_path, mode="r", encoding="utf-8") as fp:
            loaded_json = json.load(fp)
        self.assertEqual(loaded_json["evaluation_summary"]["detection_rate_percent"], 100.0)


if __name__ == "__main__":
    unittest.main()
