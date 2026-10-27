"""MedTrustEdge Phase 6 — Checkpoint Subsystem Unit Tests.

Validates independent cryptographic checkpoint generation, canonical serialization,
HMAC-SHA256 and RFC 8032 Ed25519 signing, verification, and tamper rejection.
"""
from __future__ import annotations

import unittest
from src.blockchain.checkpoint import (
    CheckpointKeyError,
    CheckpointSignatureError,
    CheckpointValidationError,
    LedgerCheckpoint,
    create_checkpoint,
    generate_ed25519_keypair,
    generate_hmac_key,
    sign_checkpoint_ed25519,
    sign_checkpoint_hmac,
    verify_checkpoint,
    verify_ledger_against_checkpoint,
)
from src.blockchain.event_adapter import EventAdapter
from src.blockchain.ledger import BlockchainLedger
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class TestPhase6Checkpoint(unittest.TestCase):
    """Test suite for Phase 6 independent cryptographic checkpointing."""

    def setUp(self) -> None:
        """Sets up a real baseline ledger for checkpoint tests."""
        p4 = BASE_DIR / "results" / "phase4" / "phase4_trust_trace.csv"
        p2 = BASE_DIR / "results" / "zerotrust" / "zerotrust_security_events.csv"
        adapter = EventAdapter()
        events = adapter.adapt(p4, p2)
        self.ledger = BlockchainLedger.build_from_events(events, batch_size=5)

    def test_01_checkpoint_schema_and_canonical_payload(self) -> None:
        """Checkpoint must enforce strict schema boundaries and deterministic canonical payload."""
        cp = LedgerCheckpoint(
            checkpoint_id="cp-001",
            timestamp_utc="2026-10-26T22:00:00Z",
            block_index=5,
            block_hash="a" * 64,
            merkle_root="b" * 64,
            total_event_count=25,
            key_id="gw-01",
            algorithm="Ed25519",
            signature="c" * 128,
        )
        cp.validate_schema()
        payload = cp.to_canonical_payload()
        self.assertIsInstance(payload, bytes)
        self.assertNotIn(b"signature", payload)
        self.assertIn(b"block_hash", payload)

    def test_02_hmac_checkpoint_sign_and_verify(self) -> None:
        """HMAC-SHA256 checkpoint must sign and verify cleanly under authentic secret key."""
        key = generate_hmac_key()
        cp = create_checkpoint(self.ledger, key_id="edge-hmac", algorithm="HMAC-SHA256", key=key)
        self.assertEqual(cp.block_index, 5)
        self.assertEqual(cp.total_event_count, 25)
        self.assertTrue(verify_checkpoint(cp, key=key))

    def test_03_hmac_tamper_detection_wrong_key(self) -> None:
        """Negative test: Verifying HMAC checkpoint with a different secret must raise CheckpointSignatureError."""
        key1 = generate_hmac_key()
        key2 = generate_hmac_key()
        cp = create_checkpoint(self.ledger, key_id="edge-hmac", algorithm="HMAC-SHA256", key=key1)
        with self.assertRaises(CheckpointSignatureError):
            verify_checkpoint(cp, key=key2)

    def test_04_hmac_tamper_detection_modified_payload(self) -> None:
        """Negative test: Altering any payload attribute must invalidate the HMAC signature."""
        key = generate_hmac_key()
        cp = create_checkpoint(self.ledger, key_id="edge-hmac", algorithm="HMAC-SHA256", key=key)
        # Mutate block hash
        cp.block_hash = "f" * 64
        with self.assertRaises(CheckpointSignatureError):
            verify_checkpoint(cp, key=key)

    def test_05_ed25519_checkpoint_sign_and_verify(self) -> None:
        """RFC 8032 Ed25519 checkpoint must sign with private key and verify with public key."""
        sk, pk = generate_ed25519_keypair()
        cp = create_checkpoint(self.ledger, key_id="edge-ed", algorithm="Ed25519", key=sk)
        self.assertEqual(cp.algorithm, "Ed25519")
        self.assertEqual(len(cp.signature), 128)  # 64 bytes = 128 hex chars
        self.assertTrue(verify_checkpoint(cp, key=pk))

    def test_06_ed25519_tamper_detection_invalid_signature(self) -> None:
        """Negative test: Corrupting signature or verifying with wrong public key must be rejected."""
        sk1, pk1 = generate_ed25519_keypair()
        _, pk2 = generate_ed25519_keypair()
        cp = create_checkpoint(self.ledger, key_id="edge-ed", algorithm="Ed25519", key=sk1)
        # Wrong public key
        with self.assertRaises(CheckpointSignatureError):
            verify_checkpoint(cp, key=pk2)
        # Corrupted signature
        cp.signature = "0" * 128
        with self.assertRaises(CheckpointSignatureError):
            verify_checkpoint(cp, key=pk1)

    def test_07_checkpoint_json_roundtrip_fidelity(self) -> None:
        """Exporting checkpoint to JSON and reloading must preserve all fields bitwise."""
        sk, pk = generate_ed25519_keypair()
        cp = create_checkpoint(self.ledger, key_id="edge-ed", algorithm="Ed25519", key=sk)
        json_str = cp.to_json()
        reloaded = LedgerCheckpoint.from_json(json_str)
        self.assertEqual(cp.checkpoint_id, reloaded.checkpoint_id)
        self.assertEqual(cp.signature, reloaded.signature)
        self.assertEqual(cp.block_hash, reloaded.block_hash)
        self.assertTrue(verify_checkpoint(reloaded, key=pk))

    def test_08_ledger_alignment_and_fork_detection(self) -> None:
        """Ledger alignment must verify authentic chains and detect total chain substitution."""
        sk, pk = generate_ed25519_keypair()
        cp = create_checkpoint(self.ledger, key_id="edge-ed", algorithm="Ed25519", key=sk)
        ok, diags = verify_ledger_against_checkpoint(self.ledger, cp, key=pk)
        self.assertTrue(ok, f"Alignment failed: {diags}")

        # Simulate fork substitution (attacker rewrites block 5 with new hash)
        cp_forged = LedgerCheckpoint(
            checkpoint_id=cp.checkpoint_id,
            timestamp_utc=cp.timestamp_utc,
            block_index=5,
            block_hash="e" * 64,  # Substitute hash
            merkle_root=cp.merkle_root,
            total_event_count=cp.total_event_count,
            key_id=cp.key_id,
            algorithm=cp.algorithm,
            signature="",
        )
        cp_forged.signature = sign_checkpoint_ed25519(cp_forged.to_canonical_payload(), sk)
        valid, diags = verify_ledger_against_checkpoint(self.ledger, cp_forged, key=pk)
        self.assertFalse(valid)
        self.assertTrue(any("Block hash mismatch" in d for d in diags))


if __name__ == "__main__":
    unittest.main()
