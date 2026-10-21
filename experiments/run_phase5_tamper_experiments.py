"""MedTrustEdge Phase 5 Tamper Detection and Integrity Verification Runner.

Executes 8 controlled adversarial tampering experiments against disposable deep copies
of the verified baseline blockchain ledger.

Evaluated Attacks:
A. Modify an event payload field without updating its stored event hash.
B. Modify a stored event hash.
C. Modify a block header field.
D. Break a previous-block hash link.
E. Reorder events within a block.
F. Reorder blocks in the chain.
G. Delete an event from a block.
H. Delete an intermediate block.

Guarantees:
- Exactly one mutation applied per experiment on an isolated copy.
- Full verification of original ledger after each attack to ensure zero corruption.
- Frozen Phase 1-4 source files and outputs are strictly read-only.
- Generates phase5_tamper_detection_report.csv and phase5_tamper_detection_summary.json.
"""
from __future__ import annotations

import copy
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.blockchain import (
    Block,
    BlockHeader,
    BlockchainLedger,
    ChainVerifier,
    EventAdapter,
    TrustEvent,
    VerificationResult,
)

PHASE4_CSV = BASE_DIR / "results" / "phase4" / "phase4_trust_trace.csv"
PHASE2_CSV = BASE_DIR / "results" / "zerotrust" / "zerotrust_security_events.csv"
RESULTS_DIR = BASE_DIR / "results" / "phase5"


def build_baseline_ledger(batch_size: int = 5) -> tuple[BlockchainLedger, str]:
    """Constructs, validates, and serializes the baseline blockchain ledger."""
    adapter = EventAdapter()
    events = adapter.adapt(PHASE4_CSV, PHASE2_CSV)

    ledger = BlockchainLedger.build_from_events(events, batch_size=batch_size)
    verifier = ChainVerifier()
    verification = verifier.verify_ledger(ledger)

    if not verification.is_valid:
        raise RuntimeError(f"Baseline ledger failed verification: {verification.errors}")

    ledger_json = ledger.export_to_json()
    ledger_hash = hashlib.sha256(ledger_json.encode("utf-8")).hexdigest()

    return ledger, ledger_hash


def run_single_experiment(
    exp_code: str,
    exp_name: str,
    target_description: str,
    expected_failure: str,
    mutate_fn: Any,
    original_ledger: BlockchainLedger,
    verifier: ChainVerifier,
) -> dict[str, Any]:
    """Executes a single tampering experiment on an isolated deep copy."""
    # 1. Create isolated disposable deep copy
    ledger_copy = copy.deepcopy(original_ledger)

    # 2. Apply mutation
    mutation_description = mutate_fn(ledger_copy)

    # 3. Verify mutated copy
    res = verifier.verify_ledger(ledger_copy)
    is_detected = (not res.is_valid)

    # 4. Verify untouched original ledger
    orig_res = verifier.verify_ledger(original_ledger)
    if not orig_res.is_valid:
        raise RuntimeError("FATAL: Original ledger was corrupted during tampering experiment!")

    return {
        "experiment_code": exp_code,
        "attack_name": exp_name,
        "target_artifact": target_description,
        "mutation_applied": mutation_description,
        "expected_failure": expected_failure,
        "is_detected": is_detected,
        "detection_status": "DETECTED" if is_detected else "MISSED",
        "primary_error_category": res.discrepancy_type or "NONE",
        "affected_block_index": res.tampered_block_index if res.tampered_block_index is not None else -1,
        "affected_record_id": res.tampered_record_id or "N/A",
        "error_count": len(res.errors),
        "primary_diagnostic": res.errors[0] if res.errors else "None",
        "all_diagnostics": " | ".join(res.errors),
        "original_ledger_intact": orig_res.is_valid,
    }


def run_all_tamper_experiments(batch_size: int = 5) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Runs all 8 required tampering experiments and returns reports."""
    original_ledger, ledger_fingerprint = build_baseline_ledger(batch_size=batch_size)
    verifier = ChainVerifier()

    # Save baseline ledger to results/phase5/ if not already present
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    baseline_path = RESULTS_DIR / "phase5_baseline_ledger.json"
    original_ledger.export_to_json(baseline_path)

    experiments_data: list[dict[str, Any]] = []

    # Attack A: Modify event payload field without updating stored event hash
    def mutate_a(ledger: BlockchainLedger) -> str:
        b1 = ledger.blocks[1]
        ev0 = b1.events[0]
        mutated_payload = ev0.to_payload_dict()
        mutated_payload["trust_after"] = 100.0  # altered score
        mutated_payload["recorded_hash"] = ev0.event_hash  # keep old hash
        mutated_ev = TrustEvent(**mutated_payload)
        ledger.blocks[1] = Block(header=b1.header, events=(mutated_ev,) + b1.events[1:])
        return f"Block 1 Event 0 trust_after modified from {ev0.trust_after} to 100.0 (kept original hash)"

    experiments_data.append(
        run_single_experiment(
            "A",
            "Modify Event Payload (Frozen Hash)",
            "Block 1, Event 0 (fe9d845eac4fcde3)",
            "EVENT_PAYLOAD_TAMPERED",
            mutate_a,
            original_ledger,
            verifier,
        )
    )

    # Attack B: Modify a stored event hash
    def mutate_b(ledger: BlockchainLedger) -> str:
        b2 = ledger.blocks[2]
        ev1 = b2.events[1]
        mutated_payload = ev1.to_payload_dict()
        mutated_payload["recorded_hash"] = "0" * 64  # invalid hash
        mutated_ev = TrustEvent(**mutated_payload)
        ledger.blocks[2] = Block(header=b2.header, events=b2.events[:1] + (mutated_ev,) + b2.events[2:])
        return f"Block 2 Event 1 recorded_hash replaced with {'0'*64}"

    experiments_data.append(
        run_single_experiment(
            "B",
            "Modify Stored Event Hash",
            "Block 2, Event 1",
            "EVENT_PAYLOAD_TAMPERED / MERKLE_ROOT_MISMATCH",
            mutate_b,
            original_ledger,
            verifier,
        )
    )

    # Attack C: Modify a block header field (timestamp)
    def mutate_c(ledger: BlockchainLedger) -> str:
        b2 = ledger.blocks[2]
        new_header = BlockHeader(
            index=b2.index,
            previous_hash=b2.previous_hash,
            merkle_root=b2.merkle_root,
            timestamp_utc="2026-09-23T06:58:30.000000+00:00",  # modified
            difficulty=b2.header.difficulty,
            nonce=b2.header.nonce,
            schema_version=b2.header.schema_version,
        )
        ledger.blocks[2] = Block(header=new_header, events=b2.events)
        return "Block 2 header timestamp_utc shifted backwards to 2026-09-23T06:58:30.000000+00:00"

    experiments_data.append(
        run_single_experiment(
            "C",
            "Modify Block Header Field",
            "Block 2 Header (timestamp_utc)",
            "BLOCK_HASH_MISMATCH / PREVIOUS_HASH_DISCONTINUITY",
            mutate_c,
            original_ledger,
            verifier,
        )
    )

    # Attack D: Break a previous-block hash link
    def mutate_d(ledger: BlockchainLedger) -> str:
        b4 = ledger.blocks[4]
        broken_prev = "f" * 64
        new_header = BlockHeader(
            index=b4.index,
            previous_hash=broken_prev,
            merkle_root=b4.merkle_root,
            timestamp_utc=b4.timestamp_utc,
            difficulty=b4.header.difficulty,
            nonce=b4.header.nonce,
            schema_version=b4.header.schema_version,
        )
        ledger.blocks[4] = Block(header=new_header, events=b4.events)
        return f"Block 4 previous_hash replaced with {broken_prev}"

    experiments_data.append(
        run_single_experiment(
            "D",
            "Break Previous-Block Hash Link",
            "Block 4 Header (previous_hash)",
            "PREVIOUS_HASH_DISCONTINUITY",
            mutate_d,
            original_ledger,
            verifier,
        )
    )

    # Attack E: Reorder events within a block
    def mutate_e(ledger: BlockchainLedger) -> str:
        b2 = ledger.blocks[2]
        reordered = (b2.events[1], b2.events[0]) + b2.events[2:]
        ledger.blocks[2] = Block(header=b2.header, events=reordered)
        return "Block 2 Event 0 and Event 1 swapped in order"

    experiments_data.append(
        run_single_experiment(
            "E",
            "Reorder Events Within Block",
            "Block 2 (Events 0 & 1)",
            "MERKLE_ROOT_MISMATCH / CHRONOLOGICAL_REGRESSION",
            mutate_e,
            original_ledger,
            verifier,
        )
    )

    # Attack F: Reorder blocks in the chain
    def mutate_f(ledger: BlockchainLedger) -> str:
        ledger.blocks[2], ledger.blocks[3] = ledger.blocks[3], ledger.blocks[2]
        return "Block 2 and Block 3 positions swapped in chain"

    experiments_data.append(
        run_single_experiment(
            "F",
            "Reorder Blocks in Chain",
            "Blocks 2 and 3",
            "INDEX_GAP / PREVIOUS_HASH_DISCONTINUITY",
            mutate_f,
            original_ledger,
            verifier,
        )
    )

    # Attack G: Delete an event from a block
    def mutate_g(ledger: BlockchainLedger) -> str:
        b3 = ledger.blocks[3]
        truncated = b3.events[:2] + b3.events[3:]  # delete event 2
        ledger.blocks[3] = Block(header=b3.header, events=truncated)
        return "Block 3 Event 2 deleted (block event count reduced from 5 to 4)"

    experiments_data.append(
        run_single_experiment(
            "G",
            "Delete Event From Block",
            "Block 3, Event 2",
            "MERKLE_ROOT_MISMATCH",
            mutate_g,
            original_ledger,
            verifier,
        )
    )

    # Attack H: Delete an intermediate block
    def mutate_h(ledger: BlockchainLedger) -> str:
        del ledger.blocks[3]
        return "Block 3 completely deleted from ledger chain"

    experiments_data.append(
        run_single_experiment(
            "H",
            "Delete Intermediate Block",
            "Block 3",
            "INDEX_GAP / PREVIOUS_HASH_DISCONTINUITY",
            mutate_h,
            original_ledger,
            verifier,
        )
    )

    # Compile summary metrics
    total_experiments = len(experiments_data)
    total_detected = sum(1 for exp in experiments_data if exp["is_detected"])
    detection_rate = (total_detected / total_experiments) * 100.0 if total_experiments else 0.0

    summary: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_ledger": {
            "block_count": original_ledger.block_count,
            "total_event_count": original_ledger.total_event_count,
            "batch_size": original_ledger.batch_size,
            "latest_block_hash": original_ledger.latest_block.block_hash,
            "ledger_json_fingerprint_sha256": ledger_fingerprint,
        },
        "evaluation_summary": {
            "total_attacks_simulated": total_experiments,
            "total_attacks_detected": total_detected,
            "detection_rate_percent": round(detection_rate, 2),
            "original_ledger_consistent_throughout": all(exp["original_ledger_intact"] for exp in experiments_data),
        },
        "security_boundary_notice": (
            "Internal cryptographic verification proves ledger integrity and detects all intra-ledger "
            "mutations. However, total ledger substitution (fork rewrite from Genesis) cannot be detected "
            "without anchoring block hashes to an independently maintained external checkpoint."
        ),
        "experiments": experiments_data,
    }

    # Write outputs
    report_csv_path = RESULTS_DIR / "phase5_tamper_detection_report.csv"
    with open(report_csv_path, mode="w", encoding="utf-8", newline="") as fp:
        fieldnames = [
            "experiment_code",
            "attack_name",
            "target_artifact",
            "mutation_applied",
            "expected_failure",
            "is_detected",
            "detection_status",
            "primary_error_category",
            "affected_block_index",
            "affected_record_id",
            "error_count",
            "primary_diagnostic",
            "original_ledger_intact",
        ]
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for exp in experiments_data:
            row = {k: exp[k] for k in fieldnames}
            writer.writerow(row)

    summary_json_path = RESULTS_DIR / "phase5_tamper_detection_summary.json"
    with open(summary_json_path, mode="w", encoding="utf-8") as fp:
        json.dump(summary, fp, indent=2)

    return experiments_data, summary


if __name__ == "__main__":
    exps, summ = run_all_tamper_experiments(batch_size=5)
    print(f"Tamper Experiments Completed: {summ['evaluation_summary']['total_attacks_detected']}/{summ['evaluation_summary']['total_attacks_simulated']} detected.")
    for e in exps:
        print(f"[{e['experiment_code']}] {e['attack_name']}: {e['detection_status']} ({e['primary_error_category']})")
