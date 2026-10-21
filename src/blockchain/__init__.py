"""MedTrustEdge Phase 5 Blockchain Package.

Provides event adaptation, canonical serialization, SHA-256 payload hashing,
binary Merkle trees with inclusion proofs, block models, sequential blockchain ledger,
and cryptographic tamper verification.
"""
from .block import (
    Block,
    BlockError,
    BlockHeader,
    create_block,
    create_genesis_block,
    BLOCK_SCHEMA_VERSION,
    DEFAULT_GENESIS_TIMESTAMP,
    GENESIS_PREVIOUS_HASH,
)
from .event_adapter import (
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
from .ledger import (
    BlockchainLedger,
    LEDGER_SCHEMA_VERSION,
    LedgerError,
)
from .merkle import (
    EMPTY_MERKLE_ROOT,
    InvalidLeafError,
    MerkleProofError,
    MerkleTree,
    MerkleTreeError,
    is_valid_hex_hash,
    verify_inclusion_proof,
)
from .verifier import (
    ChainVerifier,
    VerificationResult,
)

__all__ = [
    # Event Adapter & Hashing
    "BlockchainAdapterError",
    "DuplicatePolicy",
    "DuplicateRecordError",
    "EventAdapter",
    "SCHEMA_VERSION",
    "SchemaValidationError",
    "TrustEvent",
    "UnmatchedRecordError",
    "compute_event_hash",
    "derive_record_id",
    "to_canonical_json",
    # Merkle Tree
    "EMPTY_MERKLE_ROOT",
    "InvalidLeafError",
    "MerkleProofError",
    "MerkleTree",
    "MerkleTreeError",
    "is_valid_hex_hash",
    "verify_inclusion_proof",
    # Block & Headers
    "Block",
    "BlockError",
    "BlockHeader",
    "BLOCK_SCHEMA_VERSION",
    "DEFAULT_GENESIS_TIMESTAMP",
    "GENESIS_PREVIOUS_HASH",
    "create_block",
    "create_genesis_block",
    # Ledger
    "BlockchainLedger",
    "LEDGER_SCHEMA_VERSION",
    "LedgerError",
    # Verification
    "ChainVerifier",
    "VerificationResult",
]
