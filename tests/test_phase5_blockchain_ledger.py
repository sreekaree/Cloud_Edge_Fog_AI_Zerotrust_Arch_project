"""Unit and integration tests for MedTrustEdge Phase 5 Blockchain Ledger & Verification."""
from datetime import datetime
import hashlib
import json
from pathlib import Path
import unittest

from src.blockchain import (
    Block,
    BlockError,
    BlockHeader,
    BlockchainLedger,
    ChainVerifier,
    EMPTY_MERKLE_ROOT,
    EventAdapter,
    GENESIS_PREVIOUS_HASH,
    InvalidLeafError,
    MerkleTree,
    TrustEvent,
    VerificationResult,
    create_block,
    create_genesis_block,
    verify_inclusion_proof,
)

BASE_DIR = Path(__file__).resolve().parent.parent
PHASE4_CSV = BASE_DIR / "results" / "phase4" / "phase4_trust_trace.csv"
PHASE2_CSV = BASE_DIR / "results" / "zerotrust" / "zerotrust_security_events.csv"


class TestPhase5BlockchainLedger(unittest.TestCase):
    """Test suite covering Merkle trees, block structures, ledger operations, and verification."""

    def setUp(self):
        self.adapter = EventAdapter()
        self.events = self.adapter.adapt(PHASE4_CSV, PHASE2_CSV)
        self.verifier = ChainVerifier()

    def test_01_empty_merkle_tree(self):
        """Empty Merkle tree must return EMPTY_MERKLE_ROOT (SHA-256 of empty string)."""
        tree = MerkleTree([])
        self.assertEqual(tree.get_root(), EMPTY_MERKLE_ROOT)
        self.assertEqual(tree.get_root(), hashlib.sha256(b"").hexdigest())
        with self.assertRaises(IndexError):
            tree.get_inclusion_proof(0)

    def test_02_single_event_merkle_tree(self):
        """Single-event Merkle tree must return the leaf hash as root, with an empty proof."""
        leaf = self.events[0].event_hash
        tree = MerkleTree([leaf])
        self.assertEqual(tree.get_root(), leaf)
        proof = tree.get_inclusion_proof(0)
        self.assertEqual(proof, [])
        self.assertTrue(verify_inclusion_proof(leaf, proof, tree.get_root()))

    def test_03_odd_and_even_leaf_counts(self):
        """Merkle tree must handle even and odd leaf counts consistently via duplication."""
        # Even count (4 leaves)
        leaves_4 = [ev.event_hash for ev in self.events[:4]]
        tree_4 = MerkleTree(leaves_4)
        for i in range(4):
            proof = tree_4.get_inclusion_proof(i)
            self.assertTrue(verify_inclusion_proof(leaves_4[i], proof, tree_4.get_root()))

        # Odd count (3 leaves - duplicates last leaf)
        leaves_3 = [ev.event_hash for ev in self.events[:3]]
        tree_3 = MerkleTree(leaves_3)
        for i in range(3):
            proof = tree_3.get_inclusion_proof(i)
            self.assertTrue(verify_inclusion_proof(leaves_3[i], proof, tree_3.get_root()))

        # Odd count (5 leaves)
        leaves_5 = [ev.event_hash for ev in self.events[:5]]
        tree_5 = MerkleTree(leaves_5)
        for i in range(5):
            proof = tree_5.get_inclusion_proof(i)
            self.assertTrue(verify_inclusion_proof(leaves_5[i], proof, tree_5.get_root()))

    def test_04_inclusion_proof_valid_and_invalid(self):
        """Inclusion proof must validate correctly and reject tampered leaves or paths."""
        leaves = [ev.event_hash for ev in self.events[:5]]
        tree = MerkleTree(leaves)
        root = tree.get_root()

        # Valid proof for leaf 1
        leaf_1 = leaves[1]
        proof_1 = tree.get_inclusion_proof(1)
        self.assertTrue(verify_inclusion_proof(leaf_1, proof_1, root))

        # Tampered leaf hash
        fake_leaf = "a" * 64
        self.assertFalse(verify_inclusion_proof(fake_leaf, proof_1, root))

        # Tampered sibling hash in proof
        tampered_proof = [dict(step) for step in proof_1]
        tampered_proof[0]["hash"] = "b" * 64
        self.assertFalse(verify_inclusion_proof(leaf_1, tampered_proof, root))

        # Tampered direction in proof
        flipped_proof = [dict(step) for step in proof_1]
        flipped_proof[0]["direction"] = "left" if flipped_proof[0]["direction"] == "right" else "right"
        self.assertFalse(verify_inclusion_proof(leaf_1, flipped_proof, root))

        # Malformed leaf rejection
        with self.assertRaises(InvalidLeafError):
            MerkleTree(["not_a_hex_hash"])

    def test_05_genesis_block_creation(self):
        """Genesis block must have index 0, 64 zeros as previous hash, and empty Merkle root."""
        genesis = create_genesis_block()
        self.assertEqual(genesis.index, 0)
        self.assertEqual(genesis.previous_hash, GENESIS_PREVIOUS_HASH)
        self.assertEqual(genesis.previous_hash, "0" * 64)
        self.assertEqual(genesis.merkle_root, EMPTY_MERKLE_ROOT)
        self.assertEqual(genesis.event_count, 0)
        self.assertEqual(len(genesis.block_hash), 64)

    def test_06_deterministic_block_hashing(self):
        """Block hash must be deterministic and sensitive to every security-relevant field."""
        b1 = create_block(
            index=1,
            previous_hash="0" * 64,
            events=self.events[:2],
            timestamp_utc="2026-09-23T06:58:25.000000+00:00",
        )
        b2 = create_block(
            index=1,
            previous_hash="0" * 64,
            events=self.events[:2],
            timestamp_utc="2026-09-23T06:58:25.000000+00:00",
        )
        self.assertEqual(b1.block_hash, b2.block_hash)

        # Altering timestamp changes hash
        b_time = create_block(
            index=1,
            previous_hash="0" * 64,
            events=self.events[:2],
            timestamp_utc="2026-09-23T06:58:26.000000+00:00",
        )
        self.assertNotEqual(b1.block_hash, b_time.block_hash)

        # Altering previous_hash changes hash
        b_prev = create_block(
            index=1,
            previous_hash="1" * 64,
            events=self.events[:2],
            timestamp_utc="2026-09-23T06:58:25.000000+00:00",
        )
        self.assertNotEqual(b1.block_hash, b_prev.block_hash)

        # Altering index changes hash
        b_idx = create_block(
            index=2,
            previous_hash="0" * 64,
            events=self.events[:2],
            timestamp_utc="2026-09-23T06:58:25.000000+00:00",
        )
        self.assertNotEqual(b1.block_hash, b_idx.block_hash)

    def test_07_previous_hash_linkage(self):
        """Sequential blocks must link strictly to the previous block's SHA-256 hash."""
        ledger = BlockchainLedger.build_from_events(self.events, batch_size=5)
        for i in range(1, ledger.block_count):
            self.assertEqual(ledger.blocks[i].previous_hash, ledger.blocks[i - 1].block_hash)

    def test_08_multiple_events_per_block_and_batching(self):
        """25 events with batch size 5 must yield exactly 1 genesis block + 5 event blocks."""
        ledger = BlockchainLedger.build_from_events(self.events, batch_size=5)
        self.assertEqual(ledger.block_count, 6)
        self.assertEqual(ledger.total_event_count, 25)

        # Block 0: Genesis
        self.assertEqual(ledger.blocks[0].event_count, 0)
        # Blocks 1..5: 5 events each
        for i in range(1, 6):
            self.assertEqual(ledger.blocks[i].event_count, 5)

    def test_09_invalid_event_handling_in_block(self):
        """Blocks with mismatched Merkle roots or invalid indices must raise BlockError."""
        fake_header = BlockHeader(
            index=1,
            previous_hash="0" * 64,
            merkle_root="f" * 64,  # mismatched root
            timestamp_utc="2026-09-23T06:58:25.000000+00:00",
        )
        with self.assertRaises(BlockError):
            Block(header=fake_header, events=(self.events[0],), strict_validate=True)

        # Negative index
        with self.assertRaises(BlockError):
            BlockHeader(
                index=-1,
                previous_hash="0" * 64,
                merkle_root=EMPTY_MERKLE_ROOT,
                timestamp_utc="2026-09-23T06:58:25.000000+00:00",
            )

    def test_10_export_and_reload_roundtrip(self):
        """Exporting to JSON and reloading must produce an identical, fully valid ledger."""
        ledger = BlockchainLedger.build_from_events(self.events, batch_size=5)
        json_str = ledger.export_to_json()
        reloaded = BlockchainLedger.load_from_json(json_str)

        self.assertEqual(ledger.block_count, reloaded.block_count)
        self.assertEqual(ledger.total_event_count, reloaded.total_event_count)
        for i in range(ledger.block_count):
            b_orig = ledger.get_block(i)
            b_rel = reloaded.get_block(i)
            self.assertEqual(b_orig.block_hash, b_rel.block_hash)
            self.assertEqual(b_orig.merkle_root, b_rel.merkle_root)
            self.assertEqual(b_orig.previous_hash, b_rel.previous_hash)
            self.assertEqual(b_orig.event_count, b_rel.event_count)

        self.assertTrue(self.verifier.verify_export_reload(ledger))

    def test_11_device_history_retrieval(self):
        """Querying events for a specific device must return its complete chronological trace."""
        ledger = BlockchainLedger.build_from_events(self.events, batch_size=5)
        iotA1_events = ledger.get_events_for_device("iotA1")
        # iotA1 appears at event indices 0, 1, 2, 18, 19, 20
        self.assertEqual(len(iotA1_events), 6)
        self.assertEqual([e.event_index for e in iotA1_events], [0, 1, 2, 18, 19, 20])
        for e in iotA1_events:
            self.assertEqual(e.source_device, "iotA1")

        # iotA2 appears at event indices 3, 4, 5, 21, 22, 23, 24
        iotA2_events = ledger.get_events_for_device("iotA2")
        self.assertEqual(len(iotA2_events), 7)
        self.assertEqual([e.event_index for e in iotA2_events], [3, 4, 5, 21, 22, 23, 24])

    def test_12_detection_of_altered_event_payload(self):
        """Verifier must catch payload mutations, pinpointing block and event."""
        ledger = BlockchainLedger.build_from_events(self.events, batch_size=5)

        # Mutate Block 1, Event 0 payload (trust_after: 98.67 -> 100.0)
        orig_ev = ledger.blocks[1].events[0]
        mutated_payload = orig_ev.to_payload_dict()
        mutated_payload["trust_after"] = 100.0

        mutated_ev = TrustEvent(
            event_index=mutated_payload["event_index"],
            record_id=mutated_payload["record_id"],
            timestamp_utc=mutated_payload["timestamp_utc"],
            source_device=mutated_payload["source_device"],
            scenario=mutated_payload["scenario"],
            p2_decision=mutated_payload["p2_decision"],
            p2_reason=mutated_payload["p2_reason"],
            jit_status=mutated_payload["jit_status"],
            severity=mutated_payload["severity"],
            oof_score=mutated_payload["oof_score"],
            p_det=mutated_payload["p_det"],
            p_ai=mutated_payload["p_ai"],
            p_total=mutated_payload["p_total"],
            rec=mutated_payload["rec"],
            trust_before=mutated_payload["trust_before"],
            trust_after=mutated_payload["trust_after"],
            state_before=mutated_payload["state_before"],
            state_after=mutated_payload["state_after"],
            mapped_phase2_state=mutated_payload["mapped_phase2_state"],
            n_viol_before=mutated_payload["n_viol_before"],
            n_viol_after=mutated_payload["n_viol_after"],
            action_taken=mutated_payload["action_taken"],
            recorded_hash=orig_ev.event_hash,
        )

        # Manually assemble tampered block with mismatched event hash
        tampered_block = Block(
            header=ledger.blocks[1].header,
            events=(mutated_ev,) + ledger.blocks[1].events[1:],
        )
        ledger.blocks[1] = tampered_block

        result = self.verifier.verify_ledger(ledger)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.tampered_block_index, 1)
        self.assertEqual(result.tampered_record_id, orig_ev.record_id)
        self.assertEqual(result.discrepancy_type, "EVENT_PAYLOAD_TAMPERED")

    def test_13_detection_of_altered_block_header(self):
        """Verifier must detect altered block header hashes."""
        ledger = BlockchainLedger.build_from_events(self.events, batch_size=5)

        # Tamper Block 2 header timestamp
        orig_b2 = ledger.blocks[2]
        fake_header = BlockHeader(
            index=orig_b2.index,
            previous_hash=orig_b2.previous_hash,
            merkle_root=orig_b2.merkle_root,
            timestamp_utc="2026-09-23T06:58:30.000000+00:00",  # changed
            difficulty=orig_b2.header.difficulty,
            nonce=orig_b2.header.nonce,
            schema_version=orig_b2.header.schema_version,
        )

        tampered_b2 = Block(header=fake_header, events=orig_b2.events)
        ledger.blocks[2] = tampered_b2

        result = self.verifier.verify_ledger(ledger)
        self.assertFalse(result.is_valid)
        # Block 3 linkage will also fail because Block 2's hash shifted
        self.assertTrue(any("discontinuity" in err or "mismatch" in err for err in result.errors))

    def test_14_detection_of_broken_previous_hash_linkage(self):
        """Verifier must detect broken previous_hash links."""
        ledger = BlockchainLedger.build_from_events(self.events, batch_size=5)

        # Change previous_hash in Block 3
        orig_b3 = ledger.blocks[3]
        fake_header = BlockHeader(
            index=orig_b3.index,
            previous_hash="c" * 64,
            merkle_root=orig_b3.merkle_root,
            timestamp_utc=orig_b3.timestamp_utc,
            difficulty=orig_b3.header.difficulty,
            nonce=orig_b3.header.nonce,
            schema_version=orig_b3.header.schema_version,
        )
        tampered_b3 = Block(header=fake_header, events=orig_b3.events)
        ledger.blocks[3] = tampered_b3

        result = self.verifier.verify_ledger(ledger)
        self.assertFalse(result.is_valid)
        self.assertTrue(any("discontinuity" in err for err in result.errors))

    def test_15_preservation_of_original_event_payloads(self):
        """All sealed ledger events must match the original Phase 4 and Phase 2 values."""
        ledger = BlockchainLedger.build_from_events(self.events, batch_size=5)
        sealed_events: list[TrustEvent] = []
        for block in ledger.blocks[1:]:
            sealed_events.extend(block.events)

        self.assertEqual(len(sealed_events), 25)
        for i in range(25):
            self.assertEqual(sealed_events[i].record_id, self.events[i].record_id)
            self.assertEqual(sealed_events[i].oof_score, self.events[i].oof_score)
            self.assertEqual(sealed_events[i].trust_before, self.events[i].trust_before)
            self.assertEqual(sealed_events[i].trust_after, self.events[i].trust_after)
            self.assertEqual(sealed_events[i].p2_decision, self.events[i].p2_decision)
            self.assertEqual(sealed_events[i].p2_reason, self.events[i].p2_reason)
            self.assertEqual(sealed_events[i].timestamp_utc, self.events[i].timestamp_utc)

    def test_16_verification_detects_chronological_regression(self):
        """Verifier must detect non-chronological events across block boundaries."""
        # Create an artificial sequence where event 1 has a timestamp earlier than event 0
        p0 = self.events[0]
        regressed_ev = TrustEvent(
            event_index=1,
            record_id="regressed_0001",
            timestamp_utc="2026-09-23T06:50:00.000000+00:00",  # 8 minutes earlier
            source_device=self.events[1].source_device,
            scenario=self.events[1].scenario,
            p2_decision=self.events[1].p2_decision,
            p2_reason=self.events[1].p2_reason,
            jit_status=self.events[1].jit_status,
            severity=self.events[1].severity,
            oof_score=self.events[1].oof_score,
            p_det=self.events[1].p_det,
            p_ai=self.events[1].p_ai,
            p_total=self.events[1].p_total,
            rec=self.events[1].rec,
            trust_before=self.events[1].trust_before,
            trust_after=self.events[1].trust_after,
            state_before=self.events[1].state_before,
            state_after=self.events[1].state_after,
            mapped_phase2_state=self.events[1].mapped_phase2_state,
            n_viol_before=self.events[1].n_viol_before,
            n_viol_after=self.events[1].n_viol_after,
            action_taken=self.events[1].action_taken,
        )

        bad_ledger = BlockchainLedger(batch_size=2, initialize_genesis=True)
        b1 = create_block(
            index=1,
            previous_hash=bad_ledger.blocks[0].block_hash,
            events=[p0, regressed_ev],
        )
        bad_ledger.blocks = [bad_ledger.blocks[0], b1]

        result = self.verifier.verify_ledger(bad_ledger)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.discrepancy_type, "CHRONOLOGICAL_REGRESSION")

    def test_17_checkpoint_notice_present(self):
        """VerificationResult must include the security boundary notice regarding external checkpoints."""
        ledger = BlockchainLedger.build_from_events(self.events, batch_size=5)
        result = self.verifier.verify_ledger(ledger)
        self.assertTrue(result.is_valid)
        self.assertIn("checkpoint", result.checkpoint_notice.lower())


if __name__ == "__main__":
    unittest.main()
