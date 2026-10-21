"""Block and BlockHeader Models for MedTrustEdge Phase 5 Blockchain.

Defines the cryptographic data structures representing blocks and block headers,
canonical header serialization, SHA-256 block hashing, and genesis block generation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from .event_adapter import TrustEvent, parse_iso_timestamp, to_canonical_json
from .merkle import EMPTY_MERKLE_ROOT, MerkleTree, is_valid_hex_hash

BLOCK_SCHEMA_VERSION: str = "phase5-block-v1"
GENESIS_PREVIOUS_HASH: str = "0" * 64
DEFAULT_GENESIS_TIMESTAMP: str = "2026-09-23T06:58:00.000000+00:00"


class BlockError(Exception):
    """Base exception for block validation or creation errors."""


@dataclass(frozen=True)
class BlockHeader:
    """Cryptographic header committing to previous block, Merkle root, and metadata."""

    index: int
    previous_hash: str
    merkle_root: str
    timestamp_utc: str
    difficulty: int = 0
    nonce: int = 0
    schema_version: str = BLOCK_SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Validates all header fields."""
        self.validate()

    def validate(self) -> None:
        """Validates boundaries, indices, and cryptographic hashes."""
        if not isinstance(self.index, int) or self.index < 0:
            raise BlockError(f"Block index must be a non-negative integer, got {self.index}")

        if not is_valid_hex_hash(self.previous_hash):
            raise BlockError(f"previous_hash must be a 64-char lowercase hex hash, got '{self.previous_hash}'")

        if not is_valid_hex_hash(self.merkle_root):
            raise BlockError(f"merkle_root must be a 64-char lowercase hex hash, got '{self.merkle_root}'")

        parse_iso_timestamp(self.timestamp_utc)

        if not isinstance(self.difficulty, int) or self.difficulty < 0:
            raise BlockError(f"difficulty must be a non-negative integer, got {self.difficulty}")

        if not isinstance(self.nonce, int) or self.nonce < 0:
            raise BlockError(f"nonce must be a non-negative integer, got {self.nonce}")

    def to_header_dict(self) -> dict[str, Any]:
        """Returns the canonical dictionary representation of the header fields."""
        return {
            "difficulty": self.difficulty,
            "index": self.index,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "previous_hash": self.previous_hash,
            "schema_version": self.schema_version,
            "timestamp_utc": self.timestamp_utc,
        }

    def to_canonical_json(self) -> str:
        """Serializes the header to deterministic canonical JSON."""
        return to_canonical_json(self.to_header_dict())

    def compute_block_hash(self) -> str:
        """Computes the SHA-256 block hash from the canonical header JSON."""
        return hashlib.sha256(self.to_canonical_json().encode("utf-8")).hexdigest()

    @property
    def block_hash(self) -> str:
        """Returns the block hash."""
        return self.compute_block_hash()


@dataclass(frozen=True)
class Block:
    """A sealed blockchain block containing header metadata and ordered trust events."""

    header: BlockHeader
    events: tuple[TrustEvent, ...] = field(default_factory=tuple)
    strict_validate: bool = False

    def __post_init__(self) -> None:
        """Validates block header consistency."""
        self.header.validate()
        if self.strict_validate:
            self.validate_merkle_root()

    def validate_merkle_root(self) -> None:
        """Validates that sealed event hashes match the header's Merkle root."""
        event_hashes = [ev.event_hash for ev in self.events]
        computed_root = MerkleTree(event_hashes).get_root()
        if computed_root.lower() != self.header.merkle_root.lower():
            raise BlockError(
                f"Block {self.header.index} Merkle root mismatch: header specifies '{self.header.merkle_root}' "
                f"but event hashes yield '{computed_root}'"
            )

    @property
    def index(self) -> int:
        return self.header.index

    @property
    def previous_hash(self) -> str:
        return self.header.previous_hash

    @property
    def merkle_root(self) -> str:
        return self.header.merkle_root

    @property
    def timestamp_utc(self) -> str:
        return self.header.timestamp_utc

    @property
    def block_hash(self) -> str:
        return self.header.block_hash

    @property
    def event_count(self) -> int:
        return len(self.events)

    def to_dict(self) -> dict[str, Any]:
        """Serializes the block including its header, block_hash, and enveloped events."""
        return {
            "block_hash": self.block_hash,
            "header": self.header.to_header_dict(),
            "event_count": self.event_count,
            "events": [ev.to_enveloped_dict() for ev in self.events],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Block:
        """Deserializes a dictionary into a validated Block instance."""
        header_data = data.get("header")
        if not isinstance(header_data, dict):
            raise BlockError("Missing or invalid 'header' dictionary in block data")

        header = BlockHeader(
            index=int(header_data["index"]),
            previous_hash=str(header_data["previous_hash"]),
            merkle_root=str(header_data["merkle_root"]),
            timestamp_utc=str(header_data["timestamp_utc"]),
            difficulty=int(header_data.get("difficulty", 0)),
            nonce=int(header_data.get("nonce", 0)),
            schema_version=str(header_data.get("schema_version", BLOCK_SCHEMA_VERSION)),
        )

        raw_events = data.get("events", [])
        parsed_events: list[TrustEvent] = []
        for ev_item in raw_events:
            payload = ev_item.get("payload", ev_item)
            event = TrustEvent(
                event_index=int(payload["event_index"]),
                record_id=str(payload["record_id"]),
                timestamp_utc=str(payload["timestamp_utc"]),
                source_device=str(payload["source_device"]),
                scenario=str(payload["scenario"]),
                p2_decision=str(payload["p2_decision"]),
                p2_reason=str(payload["p2_reason"]),
                jit_status=str(payload["jit_status"]),
                severity=str(payload["severity"]),
                oof_score=float(payload["oof_score"]),
                p_det=float(payload["p_det"]),
                p_ai=float(payload["p_ai"]),
                p_total=float(payload["p_total"]),
                rec=float(payload["rec"]),
                trust_before=float(payload["trust_before"]),
                trust_after=float(payload["trust_after"]),
                state_before=str(payload["state_before"]),
                state_after=str(payload["state_after"]),
                mapped_phase2_state=str(payload["mapped_phase2_state"]),
                n_viol_before=int(payload["n_viol_before"]),
                n_viol_after=int(payload["n_viol_after"]),
                action_taken=str(payload["action_taken"]),
                metadata=payload.get("metadata"),
                schema_version=str(payload.get("schema_version", "phase5-event-v1")),
                recorded_hash=ev_item.get("event_hash"),
            )
            parsed_events.append(event)

        return cls(header=header, events=tuple(parsed_events))


def create_genesis_block(timestamp_utc: str = DEFAULT_GENESIS_TIMESTAMP) -> Block:
    """Constructs the authoritative Genesis block (index 0) with 64-zero previous hash."""
    header = BlockHeader(
        index=0,
        previous_hash=GENESIS_PREVIOUS_HASH,
        merkle_root=EMPTY_MERKLE_ROOT,
        timestamp_utc=timestamp_utc,
        difficulty=0,
        nonce=0,
        schema_version=BLOCK_SCHEMA_VERSION,
    )
    return Block(header=header, events=())


def create_block(
    index: int,
    previous_hash: str,
    events: list[TrustEvent] | tuple[TrustEvent, ...],
    timestamp_utc: str | None = None,
    difficulty: int = 0,
    nonce: int = 0,
) -> Block:
    """Constructs and seals a new block over the provided ordered events."""
    event_tuple = tuple(events)
    event_hashes = [ev.event_hash for ev in event_tuple]
    merkle_root = MerkleTree(event_hashes).get_root()

    if timestamp_utc is None:
        if event_tuple:
            timestamp_utc = event_tuple[-1].timestamp_utc
        else:
            timestamp_utc = datetime.now(timezone.utc).isoformat()

    header = BlockHeader(
        index=index,
        previous_hash=previous_hash,
        merkle_root=merkle_root,
        timestamp_utc=timestamp_utc,
        difficulty=difficulty,
        nonce=nonce,
        schema_version=BLOCK_SCHEMA_VERSION,
    )
    return Block(header=header, events=event_tuple)
