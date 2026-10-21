"""Blockchain Ledger Engine for MedTrustEdge Phase 5.

Manages the chain of sealed blocks, event mempool, batching, persistence,
device history querying, and integration with the verification engine.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TYPE_CHECKING

from .block import (
    Block,
    create_block,
    create_genesis_block,
    DEFAULT_GENESIS_TIMESTAMP,
)
from .event_adapter import TrustEvent

if TYPE_CHECKING:
    from .verifier import VerificationResult

LEDGER_SCHEMA_VERSION: str = "phase5-ledger-v1"


class LedgerError(Exception):
    """Base exception for ledger operations."""


class BlockchainLedger:
    """Sequential blockchain ledger managing sealed blocks and event batching."""

    def __init__(
        self,
        batch_size: int = 5,
        initialize_genesis: bool = True,
        genesis_timestamp: str = DEFAULT_GENESIS_TIMESTAMP,
    ) -> None:
        if not isinstance(batch_size, int) or batch_size <= 0:
            raise LedgerError(f"batch_size must be a positive integer, got {batch_size}")

        self.batch_size: int = batch_size
        self.blocks: list[Block] = []
        self.mempool: list[TrustEvent] = []

        if initialize_genesis:
            genesis = create_genesis_block(timestamp_utc=genesis_timestamp)
            self.blocks.append(genesis)

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    @property
    def total_event_count(self) -> int:
        return sum(block.event_count for block in self.blocks)

    @property
    def latest_block(self) -> Block:
        if not self.blocks:
            raise LedgerError("Ledger contains no blocks")
        return self.blocks[-1]

    def add_event(self, event: TrustEvent) -> None:
        """Appends an event to the unsealed mempool."""
        if not isinstance(event, TrustEvent):
            raise LedgerError(f"Expected TrustEvent instance, got {type(event)}")
        self.mempool.append(event)

    def seal_batch(self) -> Block | None:
        """Seals a single block if enough events exist in the mempool."""
        if len(self.mempool) < self.batch_size:
            return None

        batch = self.mempool[: self.batch_size]
        self.mempool = self.mempool[self.batch_size :]

        next_index = len(self.blocks)
        previous_hash = self.latest_block.block_hash

        new_block = create_block(
            index=next_index,
            previous_hash=previous_hash,
            events=batch,
        )
        self.blocks.append(new_block)
        return new_block

    def flush_mempool(self) -> Block | None:
        """Flushes any remaining events in the mempool into a final sealed block."""
        if not self.mempool:
            return None

        batch = list(self.mempool)
        self.mempool = []

        next_index = len(self.blocks)
        previous_hash = self.latest_block.block_hash

        new_block = create_block(
            index=next_index,
            previous_hash=previous_hash,
            events=batch,
        )
        self.blocks.append(new_block)
        return new_block

    def ingest_events(
        self,
        events: list[TrustEvent] | tuple[TrustEvent, ...],
        seal_remainder: bool = True,
    ) -> list[Block]:
        """Ingests a sequence of events, sealing blocks according to batch_size."""
        created_blocks: list[Block] = []
        for ev in events:
            self.add_event(ev)
            while len(self.mempool) >= self.batch_size:
                sealed = self.seal_batch()
                if sealed:
                    created_blocks.append(sealed)

        if seal_remainder and self.mempool:
            flushed = self.flush_mempool()
            if flushed:
                created_blocks.append(flushed)

        return created_blocks

    @classmethod
    def build_from_events(
        cls,
        events: list[TrustEvent] | tuple[TrustEvent, ...],
        batch_size: int = 5,
        genesis_timestamp: str = DEFAULT_GENESIS_TIMESTAMP,
    ) -> BlockchainLedger:
        """Factory method: creates ledger, initializes genesis, and ingests all events."""
        ledger = cls(
            batch_size=batch_size,
            initialize_genesis=True,
            genesis_timestamp=genesis_timestamp,
        )
        ledger.ingest_events(events, seal_remainder=True)
        return ledger

    def get_block(self, index: int) -> Block:
        """Retrieves a block by its height index."""
        if not (0 <= index < len(self.blocks)):
            raise IndexError(f"Block index {index} out of range (0..{len(self.blocks)-1})")
        return self.blocks[index]

    def get_events_for_device(self, device_id: str) -> list[TrustEvent]:
        """Extracts the complete chronological sequence of events for a specific device."""
        device_events: list[TrustEvent] = []
        for block in self.blocks:
            for ev in block.events:
                if ev.source_device == device_id:
                    device_events.append(ev)
        return device_events

    def to_dict(self) -> dict[str, Any]:
        """Serializes the entire ledger into a dictionary structure."""
        return {
            "ledger_schema_version": LEDGER_SCHEMA_VERSION,
            "block_count": self.block_count,
            "total_event_count": self.total_event_count,
            "batch_size": self.batch_size,
            "blocks": [block.to_dict() for block in self.blocks],
        }

    def export_to_json(self, output_path: str | Path | None = None, indent: int = 2) -> str:
        """Exports the ledger to formatted JSON, optionally writing to disk."""
        data_dict = self.to_dict()
        json_str = json.dumps(data_dict, indent=indent, ensure_ascii=False)
        if output_path is not None:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, mode="w", encoding="utf-8") as fp:
                fp.write(json_str)
        return json_str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BlockchainLedger:
        """Reconstructs a BlockchainLedger instance from a serialized dictionary."""
        batch_size = int(data.get("batch_size", 5))
        ledger = cls(batch_size=batch_size, initialize_genesis=False)

        raw_blocks = data.get("blocks", [])
        for block_data in raw_blocks:
            block = Block.from_dict(block_data)
            ledger.blocks.append(block)

        return ledger

    @classmethod
    def load_from_json(cls, json_str_or_path: str | Path) -> BlockchainLedger:
        """Loads and deserializes a ledger from a JSON string or file path."""
        p = Path(json_str_or_path)
        if p.is_file():
            with open(p, mode="r", encoding="utf-8") as fp:
                data = json.load(fp)
        else:
            data = json.loads(str(json_str_or_path))

        return cls.from_dict(data)

    def verify(self) -> VerificationResult:
        """Executes full cryptographic and structural verification of this ledger."""
        from .verifier import ChainVerifier

        return ChainVerifier().verify_ledger(self)
