"""Event Adapter and Canonical SHA-256 Hashing Engine for MedTrustEdge Phase 5.

Normalizes preserved Phase 4 dynamic trust trace events and Phase 2 Zero Trust
audit events into canonical, tamper-evident audit records.

Enforces:
- Schema versioning and strict field validation.
- Verified record identifier joining (Phase 4 record_id <-> Phase 2 record_id).
- Stable canonical JSON serialization (sorted keys, compact separators, UTF-8).
- SHA-256 hashing strictly over the event payload (hash never inside payload).
- Duplicate identifier detection and configurable policy.
- Stable chronological ordering with event_index as tie-breaker.
- Absolute preservation of Phase 2 decisions and Phase 4 trust scores.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION: str = "phase5-event-v1"

PHASE4_REQUIRED_COLUMNS: tuple[str, ...] = (
    "event_index",
    "record_id",
    "source_device",
    "scenario",
    "p2_decision",
    "p2_reason",
    "jit_status",
    "severity",
    "oof_score",
    "p_det",
    "p_ai",
    "p_total",
    "rec",
    "trust_before",
    "trust_after",
    "state_before",
    "state_after",
    "mapped_phase2_state",
    "n_viol_before",
    "n_viol_after",
    "action_taken",
)

PHASE2_REQUIRED_COLUMNS: tuple[str, ...] = (
    "timestamp_utc",
    "scenario",
    "device_id",
)

VALID_DECISIONS: frozenset[str] = frozenset({"ALLOW", "DENY"})
VALID_DYNAMIC_STATES: frozenset[str] = frozenset({"TRUSTED", "RESTRICTED", "REVOKED"})
VALID_PHASE2_STATES: frozenset[str] = frozenset({"TRUSTED", "SUSPICIOUS", "REVOKED"})
VALID_SEVERITIES: frozenset[str] = frozenset({"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"})


class BlockchainAdapterError(Exception):
    """Base exception for Phase 5 blockchain event adapter errors."""


class SchemaValidationError(BlockchainAdapterError):
    """Raised when an event record fails structural or semantic schema validation."""


class UnmatchedRecordError(BlockchainAdapterError):
    """Raised when a Phase 4 event identifier cannot be matched to Phase 2 audit data."""


class DuplicateRecordError(BlockchainAdapterError):
    """Raised when a duplicate record identifier is detected in violation of policy."""


class DuplicatePolicy(str, Enum):
    """Policy for handling duplicate record identifiers during event adaptation."""

    REJECT = "REJECT"
    WARN_AND_SKIP = "WARN_AND_SKIP"


def derive_record_id(timestamp_utc: str, device_id: str, destination_ip: str, scenario: str) -> str:
    """Computes the authoritative 16-hex character record_id from Phase 2 audit fields.

    Reproduces the exact deterministic derivation function established in Phase 3A:
    hashlib.sha256(f"{timestamp_utc}|{device_id}|{destination_ip}|{scenario}".encode()).hexdigest()[:16]
    """
    stable_repr = "|".join((str(timestamp_utc).strip(), str(device_id).strip(), str(destination_ip).strip(), str(scenario).strip()))
    return hashlib.sha256(stable_repr.encode("utf-8")).hexdigest()[:16]


def parse_iso_timestamp(timestamp_str: str) -> datetime:
    """Parses and validates an ISO 8601 UTC timestamp string."""
    try:
        normalized = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception as exc:
        raise SchemaValidationError(f"Invalid ISO 8601 UTC timestamp: '{timestamp_str}'") from exc


def to_canonical_json(payload: dict[str, Any]) -> str:
    """Serializes a dictionary to deterministic, canonical JSON format.

    Guarantees:
    - Sorted keys (sort_keys=True)
    - Compact delimiters with no trailing whitespace (separators=(',', ':'))
    - Standard UTF-8 character preservation (ensure_ascii=False)
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_event_hash(canonical_json_str: str) -> str:
    """Computes SHA-256 hex digest of the canonical JSON string.

    The hash is calculated strictly over the payload bytes. The hash is NEVER
    contained inside the payload being hashed.
    """
    return hashlib.sha256(canonical_json_str.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TrustEvent:
    """Normalized, immutable Zero Trust and Dynamic Trust audit event.

    Contains all 21 Phase 4 trace fields paired with the authoritative Phase 2
    UTC timestamp, formatted for cryptographic ledger inclusion.
    """

    event_index: int
    record_id: str
    timestamp_utc: str
    source_device: str
    scenario: str
    p2_decision: str
    p2_reason: str
    jit_status: str
    severity: str
    oof_score: float
    p_det: float
    p_ai: float
    p_total: float
    rec: float
    trust_before: float
    trust_after: float
    state_before: str
    state_after: str
    mapped_phase2_state: str
    n_viol_before: int
    n_viol_after: int
    action_taken: str
    metadata: dict[str, Any] | None = field(default=None)
    schema_version: str = field(default=SCHEMA_VERSION)
    recorded_hash: str | None = field(default=None)

    def __post_init__(self) -> None:
        """Validates all fields upon instantiation."""
        self.validate()

    def validate(self) -> None:
        """Performs comprehensive validation of event fields and boundaries."""
        if not isinstance(self.event_index, int) or self.event_index < 0:
            raise SchemaValidationError(f"event_index must be a non-negative integer, got {self.event_index}")

        if not self.record_id or not isinstance(self.record_id, str):
            raise SchemaValidationError(f"record_id must be a non-empty string, got {self.record_id!r}")

        parse_iso_timestamp(self.timestamp_utc)

        if not self.source_device or not isinstance(self.source_device, str):
            raise SchemaValidationError(f"source_device must be a non-empty string, got {self.source_device!r}")

        if self.p2_decision not in VALID_DECISIONS:
            raise SchemaValidationError(f"Invalid p2_decision '{self.p2_decision}'. Must be one of {sorted(VALID_DECISIONS)}")

        if self.severity not in VALID_SEVERITIES:
            raise SchemaValidationError(f"Invalid severity '{self.severity}'. Must be one of {sorted(VALID_SEVERITIES)}")

        if not (0.0 <= self.oof_score <= 1.0):
            raise SchemaValidationError(f"oof_score must be in range [0.0, 1.0], got {self.oof_score}")

        for score_name, score_val in [("trust_before", self.trust_before), ("trust_after", self.trust_after)]:
            if not (0.0 <= score_val <= 100.0):
                raise SchemaValidationError(f"{score_name} must be in range [0.0, 100.0], got {score_val}")

        for state_name, state_val in [("state_before", self.state_before), ("state_after", self.state_after)]:
            if state_val not in VALID_DYNAMIC_STATES:
                raise SchemaValidationError(f"Invalid {state_name} '{state_val}'. Must be in {sorted(VALID_DYNAMIC_STATES)}")

        if self.mapped_phase2_state not in VALID_PHASE2_STATES:
            raise SchemaValidationError(
                f"Invalid mapped_phase2_state '{self.mapped_phase2_state}'. Must be in {sorted(VALID_PHASE2_STATES)}"
            )

        for viol_name, viol_val in [("n_viol_before", self.n_viol_before), ("n_viol_after", self.n_viol_after)]:
            if not isinstance(viol_val, int) or viol_val < 0:
                raise SchemaValidationError(f"{viol_name} must be a non-negative integer, got {viol_val}")

        if self.metadata is not None and not isinstance(self.metadata, dict):
            raise SchemaValidationError(f"metadata must be a dictionary or None, got {type(self.metadata)}")

    def to_payload_dict(self) -> dict[str, Any]:
        """Returns the canonical event payload dictionary.

        CRITICAL: The event hash is intentionally EXCLUDED from this payload.
        The hash is computed over the serialized representation of this dictionary.
        """
        payload: dict[str, Any] = {
            "action_taken": self.action_taken,
            "event_index": self.event_index,
            "jit_status": self.jit_status,
            "mapped_phase2_state": self.mapped_phase2_state,
            "n_viol_after": self.n_viol_after,
            "n_viol_before": self.n_viol_before,
            "oof_score": round(float(self.oof_score), 4),
            "p_ai": round(float(self.p_ai), 2),
            "p_det": round(float(self.p_det), 2),
            "p_total": round(float(self.p_total), 2),
            "p2_decision": self.p2_decision,
            "p2_reason": self.p2_reason,
            "rec": round(float(self.rec), 2),
            "record_id": self.record_id,
            "scenario": self.scenario,
            "schema_version": self.schema_version,
            "severity": self.severity,
            "source_device": self.source_device,
            "state_after": self.state_after,
            "state_before": self.state_before,
            "timestamp_utc": self.timestamp_utc,
            "trust_after": round(float(self.trust_after), 2),
            "trust_before": round(float(self.trust_before), 2),
        }
        if self.metadata is not None:
            payload["metadata"] = self.metadata
        return payload

    def to_canonical_json(self) -> str:
        """Serializes the canonical payload dictionary to deterministic JSON."""
        return to_canonical_json(self.to_payload_dict())

    def compute_hash(self) -> str:
        """Computes the SHA-256 hash strictly over the canonical event payload."""
        return compute_event_hash(self.to_canonical_json())

    @property
    def event_hash(self) -> str:
        """Returns the canonical event SHA-256 hash or recorded hash if preset."""
        if self.recorded_hash is not None:
            return self.recorded_hash
        return self.compute_hash()

    def to_enveloped_dict(self) -> dict[str, Any]:
        """Returns an enveloped structure containing the event hash alongside the payload."""
        return {
            "event_hash": self.event_hash,
            "payload": self.to_payload_dict(),
        }


class EventAdapter:
    """Loads, validates, pairs, and normalizes Phase 4 and Phase 2 security events."""

    def __init__(self, duplicate_policy: DuplicatePolicy = DuplicatePolicy.REJECT) -> None:
        self.duplicate_policy = duplicate_policy

    def load_phase2_events(self, source: str | Path | list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Loads Phase 2 audit events and indexes them by their verified record_id.

        Does not modify source files. If record_id is absent from the CSV,
        computes it deterministically using derive_record_id().
        """
        raw_rows: list[dict[str, Any]] = []
        if isinstance(source, (str, Path)):
            src_path = Path(source)
            if not src_path.is_file():
                raise FileNotFoundError(f"Phase 2 audit file not found: {src_path}")
            with open(src_path, mode="r", encoding="utf-8", newline="") as fp:
                reader = csv.DictReader(fp)
                raw_rows = list(reader)
        elif isinstance(source, list):
            raw_rows = [dict(row) for row in source]
        else:
            raise TypeError(f"Unsupported source type: {type(source)}")

        events_by_id: dict[str, dict[str, Any]] = {}
        for idx, row in enumerate(raw_rows):
            for col in PHASE2_REQUIRED_COLUMNS:
                if col not in row or row[col] is None or str(row[col]).strip() == "":
                    raise SchemaValidationError(f"Phase 2 row {idx} is missing required column '{col}'")

            rec_id = str(row.get("record_id", "")).strip()
            if not rec_id:
                dest_ip = str(row.get("destination_ip", "")).strip()
                rec_id = derive_record_id(row["timestamp_utc"], row["device_id"], dest_ip, row["scenario"])

            if rec_id in events_by_id:
                if self.duplicate_policy == DuplicatePolicy.REJECT:
                    raise DuplicateRecordError(f"Duplicate record_id '{rec_id}' detected in Phase 2 audit records at index {idx}")
                elif self.duplicate_policy == DuplicatePolicy.WARN_AND_SKIP:
                    continue

            parsed_row = dict(row)
            parsed_row["record_id"] = rec_id
            events_by_id[rec_id] = parsed_row

        return events_by_id

    def load_phase4_trace(self, source: str | Path | list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Loads Phase 4 trust trace events without modifying source files."""
        raw_rows: list[dict[str, Any]] = []
        if isinstance(source, (str, Path)):
            src_path = Path(source)
            if not src_path.is_file():
                raise FileNotFoundError(f"Phase 4 trace file not found: {src_path}")
            with open(src_path, mode="r", encoding="utf-8", newline="") as fp:
                reader = csv.DictReader(fp)
                raw_rows = list(reader)
        elif isinstance(source, list):
            raw_rows = [dict(row) for row in source]
        else:
            raise TypeError(f"Unsupported source type: {type(source)}")

        for idx, row in enumerate(raw_rows):
            for col in PHASE4_REQUIRED_COLUMNS:
                if col not in row or row[col] is None or str(row[col]).strip() == "":
                    raise SchemaValidationError(f"Phase 4 row {idx} is missing required column '{col}'")

        return raw_rows

    def adapt_single_record(
        self,
        p4_row: dict[str, Any],
        p2_event: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> TrustEvent:
        """Adapts and normalizes a single paired Phase 4 and Phase 2 record."""
        p4_rec_id = str(p4_row["record_id"]).strip()
        p2_rec_id = str(p2_event["record_id"]).strip()

        if p4_rec_id != p2_rec_id:
            raise SchemaValidationError(
                f"Identifier mismatch in record pairing: Phase 4 '{p4_rec_id}' vs Phase 2 '{p2_rec_id}'"
            )

        p4_device = str(p4_row["source_device"]).strip()
        p2_device = str(p2_event["device_id"]).strip()
        if p4_device != p2_device:
            raise SchemaValidationError(
                f"Device mismatch for record '{p4_rec_id}': Phase 4 '{p4_device}' vs Phase 2 '{p2_device}'"
            )

        p4_scenario = str(p4_row["scenario"]).strip()
        p2_scenario = str(p2_event["scenario"]).strip()
        if p4_scenario != p2_scenario:
            raise SchemaValidationError(
                f"Scenario mismatch for record '{p4_rec_id}': Phase 4 '{p4_scenario}' vs Phase 2 '{p2_scenario}'"
            )

        p4_decision = str(p4_row["p2_decision"]).strip()
        p2_decision = str(p2_event.get("decision", p4_decision)).strip()
        if p4_decision != p2_decision:
            raise SchemaValidationError(
                f"Decision mismatch for record '{p4_rec_id}': Phase 4 '{p4_decision}' vs Phase 2 '{p2_decision}'"
            )

        timestamp_utc = str(p2_event["timestamp_utc"]).strip()

        try:
            return TrustEvent(
                event_index=int(p4_row["event_index"]),
                record_id=p4_rec_id,
                timestamp_utc=timestamp_utc,
                source_device=p4_device,
                scenario=p4_scenario,
                p2_decision=p4_decision,
                p2_reason=str(p4_row["p2_reason"]).strip(),
                jit_status=str(p4_row["jit_status"]).strip(),
                severity=str(p4_row["severity"]).strip(),
                oof_score=round(float(p4_row["oof_score"]), 4),
                p_det=round(float(p4_row["p_det"]), 2),
                p_ai=round(float(p4_row["p_ai"]), 2),
                p_total=round(float(p4_row["p_total"]), 2),
                rec=round(float(p4_row["rec"]), 2),
                trust_before=round(float(p4_row["trust_before"]), 2),
                trust_after=round(float(p4_row["trust_after"]), 2),
                state_before=str(p4_row["state_before"]).strip(),
                state_after=str(p4_row["state_after"]).strip(),
                mapped_phase2_state=str(p4_row["mapped_phase2_state"]).strip(),
                n_viol_before=int(p4_row["n_viol_before"]),
                n_viol_after=int(p4_row["n_viol_after"]),
                action_taken=str(p4_row["action_taken"]).strip(),
                metadata=metadata,
                schema_version=SCHEMA_VERSION,
            )
        except (ValueError, TypeError) as exc:
            raise SchemaValidationError(f"Type conversion failed for record '{p4_rec_id}': {exc}") from exc

    def adapt(
        self,
        phase4_source: str | Path | list[dict[str, Any]],
        phase2_source: str | Path | list[dict[str, Any]] | dict[str, dict[str, Any]],
    ) -> list[TrustEvent]:
        """Ingests, joins, validates, and chronologically sorts Phase 4 and Phase 2 events.

        - Joins strictly on verified record_id.
        - Rejects unmatched or duplicate records.
        - Sorts by (timestamp_utc, event_index) as stable tie-breaker.
        - Preserves all source values without modifying source files.
        """
        if isinstance(phase2_source, dict):
            p2_events = phase2_source
        else:
            p2_events = self.load_phase2_events(phase2_source)

        p4_rows = self.load_phase4_trace(phase4_source)

        seen_records: set[str] = set()
        adapted_events: list[TrustEvent] = []

        for idx, row in enumerate(p4_rows):
            rec_id = str(row["record_id"]).strip()
            if rec_id in seen_records:
                if self.duplicate_policy == DuplicatePolicy.REJECT:
                    raise DuplicateRecordError(f"Duplicate record_id '{rec_id}' detected in Phase 4 trace at row {idx}")
                elif self.duplicate_policy == DuplicatePolicy.WARN_AND_SKIP:
                    continue

            seen_records.add(rec_id)

            if rec_id not in p2_events:
                raise UnmatchedRecordError(
                    f"Phase 4 record '{rec_id}' (event_index={row.get('event_index', idx)}) "
                    f"has no matching Phase 2 audit event"
                )

            p2_ev = p2_events[rec_id]
            adapted_ev = self.adapt_single_record(row, p2_ev)
            adapted_events.append(adapted_ev)

        # Stable chronological ordering: primary key = timestamp_utc, secondary key = event_index
        adapted_events.sort(key=lambda ev: (parse_iso_timestamp(ev.timestamp_utc), ev.event_index))

        return adapted_events
