"""Verification Engine and Forensic Audit Validator for MedTrustEdge Phase 5.

Performs exhaustive cryptographic and structural verification of the blockchain ledger:
- Event payload canonical serialization and SHA-256 hash validation.
- Merkle tree reconstruction and block header Merkle root verification.
- Block header canonical serialization and block hash verification.
- Previous-block hash pointer linkage verification.
- Strictly monotonic block height sequence verification.
- Chronological event ordering and tie-breaker validation.
- Inclusion proof generation and validation for all sealed events.
- Ledger export / reload roundtrip persistence verification.

SECURITY BOUNDARY NOTE:
Cryptographic verification confirms internal mathematical and structural integrity
of the evaluated chain. However, internal consistency ALONE does not prove that an
adversary did not replace the entire ledger from Genesis (fork replacement). Complete
tamper detection against total chain replacement requires anchoring block hashes
to a trusted external checkpoint (e.g., Cloud compliance notarization or multi-tenant
witness signatures).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .block import Block, GENESIS_PREVIOUS_HASH
from .event_adapter import parse_iso_timestamp, to_canonical_json, compute_event_hash
from .ledger import BlockchainLedger
from .merkle import EMPTY_MERKLE_ROOT, MerkleTree, verify_inclusion_proof


@dataclass
class VerificationResult:
    """Detailed forensic result from blockchain ledger verification."""

    is_valid: bool
    block_count: int
    event_count: int
    errors: list[str] = field(default_factory=list)
    tampered_block_index: int | None = None
    tampered_record_id: str | None = None
    discrepancy_type: str | None = None
    checkpoint_notice: str = (
        "Internal cryptographic integrity verified. Note: Full protection against "
        "complete historical rewrite (fork substitution) requires external checkpoint anchoring."
    )

    def add_error(
        self,
        msg: str,
        block_index: int | None = None,
        record_id: str | None = None,
        discrepancy_type: str | None = None,
    ) -> None:
        """Records a forensic validation error and sets the failure flag."""
        self.is_valid = False
        self.errors.append(msg)
        if self.tampered_block_index is None and block_index is not None:
            self.tampered_block_index = block_index
        if self.tampered_record_id is None and record_id is not None:
            self.tampered_record_id = record_id
        if self.discrepancy_type is None and discrepancy_type is not None:
            self.discrepancy_type = discrepancy_type


class ChainVerifier:
    """Performs comprehensive integrity audits across the blockchain ledger."""

    def verify_ledger(self, ledger: BlockchainLedger) -> VerificationResult:
        """Executes full verification over all blocks and events in the ledger."""
        result = VerificationResult(
            is_valid=True,
            block_count=ledger.block_count,
            event_count=ledger.total_event_count,
        )

        if not ledger.blocks:
            result.add_error("Ledger is empty (no blocks present)", discrepancy_type="EMPTY_LEDGER")
            return result

        # 1. Verify Genesis Block (Block 0)
        genesis = ledger.blocks[0]
        if genesis.index != 0:
            result.add_error(
                f"Genesis block index must be 0, got {genesis.index}",
                block_index=0,
                discrepancy_type="GENESIS_INDEX_ERROR",
            )
        if genesis.previous_hash != GENESIS_PREVIOUS_HASH:
            result.add_error(
                f"Genesis block previous_hash must be '{GENESIS_PREVIOUS_HASH}', got '{genesis.previous_hash}'",
                block_index=0,
                discrepancy_type="GENESIS_PREV_HASH_ERROR",
            )
        if genesis.event_count == 0 and genesis.merkle_root != EMPTY_MERKLE_ROOT:
            result.add_error(
                f"Empty genesis block Merkle root must be '{EMPTY_MERKLE_ROOT}', got '{genesis.merkle_root}'",
                block_index=0,
                discrepancy_type="GENESIS_MERKLE_ERROR",
            )

        # 2. Sequential Block & Linkage Verification
        prev_block_hash = GENESIS_PREVIOUS_HASH
        prev_event_timestamp: datetime | None = None
        prev_event_index: int = -1

        for b_idx, block in enumerate(ledger.blocks):
            # Verify block height index continuity
            if block.index != b_idx:
                result.add_error(
                    f"Block at position {b_idx} has sequential index {block.index} (expected {b_idx})",
                    block_index=b_idx,
                    discrepancy_type="INDEX_GAP",
                )

            # Verify block hash computation
            expected_block_hash = block.header.compute_block_hash()
            if block.block_hash != expected_block_hash:
                result.add_error(
                    f"Block {b_idx} header hash mismatch: computed '{expected_block_hash}' vs recorded '{block.block_hash}'",
                    block_index=b_idx,
                    discrepancy_type="BLOCK_HASH_MISMATCH",
                )

            # Verify previous_hash linkage
            if b_idx > 0:
                if block.previous_hash != prev_block_hash:
                    result.add_error(
                        f"Block {b_idx} previous_hash discontinuity: header links to '{block.previous_hash}' "
                        f"but Block {b_idx-1} hash is '{prev_block_hash}'",
                        block_index=b_idx,
                        discrepancy_type="PREVIOUS_HASH_DISCONTINUITY",
                    )
            prev_block_hash = block.block_hash

            # 3. Verify Events within Block
            block_event_hashes: list[str] = []
            for ev_idx, event in enumerate(block.events):
                # Verify event payload integrity and SHA-256 hash
                canonical_json = to_canonical_json(event.to_payload_dict())
                recomputed_event_hash = compute_event_hash(canonical_json)
                if event.event_hash != recomputed_event_hash:
                    result.add_error(
                        f"Block {b_idx} Event {ev_idx} (record_id={event.record_id}) hash mismatch: "
                        f"recomputed '{recomputed_event_hash}' vs recorded '{event.event_hash}'",
                        block_index=b_idx,
                        record_id=event.record_id,
                        discrepancy_type="EVENT_PAYLOAD_TAMPERED",
                    )

                block_event_hashes.append(event.event_hash)

                # Verify chronological event ordering and sequence monotonic progression
                ev_time = parse_iso_timestamp(event.timestamp_utc)
                if prev_event_timestamp is not None:
                    if ev_time < prev_event_timestamp:
                        result.add_error(
                            f"Block {b_idx} Event {ev_idx} timestamp regressed: {event.timestamp_utc} < {prev_event_timestamp.isoformat()}",
                            block_index=b_idx,
                            record_id=event.record_id,
                            discrepancy_type="CHRONOLOGICAL_REGRESSION",
                        )
                    elif ev_time == prev_event_timestamp and event.event_index <= prev_event_index:
                        result.add_error(
                            f"Block {b_idx} Event {ev_idx} sequence tie-breaker regressed: {event.event_index} <= {prev_event_index}",
                            block_index=b_idx,
                            record_id=event.record_id,
                            discrepancy_type="EVENT_INDEX_REGRESSION",
                        )

                prev_event_timestamp = ev_time
                prev_event_index = event.event_index

            # 4. Verify Merkle Root
            tree = MerkleTree(block_event_hashes)
            recomputed_merkle_root = tree.get_root()
            if block.merkle_root != recomputed_merkle_root:
                result.add_error(
                    f"Block {b_idx} Merkle root mismatch: computed '{recomputed_merkle_root}' "
                    f"vs header '{block.merkle_root}'",
                    block_index=b_idx,
                    discrepancy_type="MERKLE_ROOT_MISMATCH",
                )

            # 5. Verify Inclusion Proof for each event in this block
            if block.event_count > 0:
                for ev_idx, event in enumerate(block.events):
                    proof = tree.get_inclusion_proof(ev_idx)
                    is_valid_proof = verify_inclusion_proof(event.event_hash, proof, block.merkle_root)
                    if not is_valid_proof:
                        result.add_error(
                            f"Block {b_idx} Event {ev_idx} inclusion proof failed against Merkle root '{block.merkle_root}'",
                            block_index=b_idx,
                            record_id=event.record_id,
                            discrepancy_type="INCLUSION_PROOF_FAILURE",
                        )

        return result

    def verify_export_reload(self, ledger: BlockchainLedger) -> bool:
        """Verifies that exporting and reloading the ledger preserves bitwise and semantic integrity."""
        exported_json = ledger.export_to_json()
        reloaded_ledger = BlockchainLedger.load_from_json(exported_json)
        verification = self.verify_ledger(reloaded_ledger)
        if not verification.is_valid:
            return False

        if ledger.block_count != reloaded_ledger.block_count:
            return False
        if ledger.total_event_count != reloaded_ledger.total_event_count:
            return False

        for i in range(ledger.block_count):
            b_orig = ledger.get_block(i)
            b_reloaded = reloaded_ledger.get_block(i)
            if b_orig.block_hash != b_reloaded.block_hash:
                return False
            if b_orig.merkle_root != b_reloaded.merkle_root:
                return False
            if b_orig.event_count != b_reloaded.event_count:
                return False

        return True
