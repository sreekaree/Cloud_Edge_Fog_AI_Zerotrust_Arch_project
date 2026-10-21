"""Unit and Integration Tests for Phase 5 Performance Benchmarking and Ablation Suite.

Validates:
1. Determinism and schema compliance of synthetic workload generators.
2. Numerical validity of benchmarking harness outputs (mean, std, min, max, throughput, peak memory).
3. Ablation verification functions (structural-only vs. inclusion-proofs-only).
4. Exported CSV schema, row count, column definitions, and numeric ranges.
5. Exported JSON summary schema, baseline metric fidelity, and security disclaimer.
6. Integrity and preservation of Part 4 artifacts.
7. Generation and validity of all diagnostic PNG plots.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
import unittest

from src.blockchain import (
    BlockchainLedger,
    ChainVerifier,
    EventAdapter,
    MerkleTree,
    TrustEvent,
)
from experiments.run_phase5_performance_benchmarks import (
    benchmark_op,
    generate_deterministic_synthetic_events,
    generate_deterministic_synthetic_raw_dicts,
    verify_without_inclusion_proofs,
    verify_inclusion_proofs_only,
)

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results" / "phase5"
PHASE4_CSV = BASE_DIR / "results" / "phase4" / "phase4_trust_trace.csv"
PHASE2_CSV = BASE_DIR / "results" / "zerotrust" / "zerotrust_security_events.csv"


class TestPhase5PerformanceBenchmarks(unittest.TestCase):
    """Test suite for Phase 5 benchmarking harness, outputs, and ablation logic."""

    def test_01_synthetic_generator_determinism_and_schema(self) -> None:
        """Synthetic generator must be 100% deterministic and pass all schema validations."""
        events_run1 = generate_deterministic_synthetic_events(50)
        events_run2 = generate_deterministic_synthetic_events(50)

        self.assertEqual(len(events_run1), 50)
        self.assertEqual(len(events_run2), 50)

        for e1, e2 in zip(events_run1, events_run2):
            self.assertEqual(e1.record_id, e2.record_id)
            self.assertEqual(e1.event_index, e2.event_index)
            self.assertEqual(e1.timestamp_utc, e2.timestamp_utc)
            self.assertEqual(e1.event_hash, e2.event_hash)
            self.assertEqual(e1.trust_before, e2.trust_before)
            self.assertEqual(e1.trust_after, e2.trust_after)
            # Schema validation
            e1.validate()

        # Check strictly monotonic timestamps
        for i in range(len(events_run1) - 1):
            self.assertLess(events_run1[i].timestamp_utc, events_run1[i + 1].timestamp_utc)

    def test_02_synthetic_raw_dicts_adaptation_fidelity(self) -> None:
        """Synthetic raw dictionaries must adapt cleanly without schema or joining errors."""
        p4_raw, p2_raw = generate_deterministic_synthetic_raw_dicts(30)
        adapter = EventAdapter()
        events = adapter.adapt(p4_raw, p2_raw)

        self.assertEqual(len(events), 30)
        self.assertEqual(events[0].event_index, 0)
        self.assertEqual(events[-1].event_index, 29)

    def test_03_benchmark_harness_measurements_validity(self) -> None:
        """Benchmarking harness must return logically consistent timing and memory numbers."""
        def dummy_workload():
            total = sum(i * i for i in range(5000))
            return total

        m = benchmark_op(dummy_workload, repetitions=10, warmup=2, track_memory=True)

        self.assertIn("mean_ms", m)
        self.assertIn("std_ms", m)
        self.assertIn("min_ms", m)
        self.assertIn("max_ms", m)
        self.assertIn("peak_kb", m)

        self.assertGreater(m["mean_ms"], 0.0)
        self.assertLessEqual(m["min_ms"], m["mean_ms"])
        self.assertGreaterEqual(m["max_ms"], m["mean_ms"])
        self.assertGreaterEqual(m["std_ms"], 0.0)
        self.assertGreaterEqual(m["peak_kb"], 0.0)

    def test_04_verification_ablation_helpers(self) -> None:
        """Ablation verification helpers must correctly validate untouched and tampered chains."""
        events = generate_deterministic_synthetic_events(20)
        ledger = BlockchainLedger.build_from_events(events, batch_size=5)

        # Baseline ledger must pass both ablation checks
        verifier = ChainVerifier()
        self.assertTrue(verify_without_inclusion_proofs(verifier, ledger))
        self.assertTrue(verify_inclusion_proofs_only(ledger))

        # Tampering with Merkle root must cause structural check to fail
        import copy
        tampered_ledger = copy.deepcopy(ledger)
        tampered_block = tampered_ledger.blocks[1]
        tampered_header = tampered_block.header.__class__(
            index=tampered_block.header.index,
            previous_hash=tampered_block.header.previous_hash,
            merkle_root="0" * 64,  # Corrupted root
            timestamp_utc=tampered_block.header.timestamp_utc,
            difficulty=0,
            nonce=0,
        )
        object.__setattr__(tampered_block, "header", tampered_header)
        self.assertFalse(verify_without_inclusion_proofs(verifier, tampered_ledger))

    def test_05_benchmark_csv_output_schema_and_validity(self) -> None:
        """Exported CSV report must exist, match schema, and contain valid numerical metrics."""
        csv_path = RESULTS_DIR / "phase5_performance_benchmarks.csv"
        self.assertTrue(csv_path.is_file(), f"Missing CSV benchmark file: {csv_path}")

        expected_cols = [
            "benchmark_id",
            "category",
            "operation",
            "workload_type",
            "event_count",
            "batch_size",
            "block_count",
            "repetitions",
            "mean_time_ms",
            "std_time_ms",
            "min_time_ms",
            "max_time_ms",
            "throughput_eps",
            "peak_memory_kb",
            "description",
        ]

        with open(csv_path, mode="r", encoding="utf-8") as fp:
            reader = csv.DictReader(fp)
            rows = list(reader)

        self.assertGreaterEqual(len(rows), 68, "Expected at least 68 benchmark records")

        for col in expected_cols:
            self.assertIn(col, reader.fieldnames or [])

        for row in rows:
            self.assertTrue(row["benchmark_id"].startswith("BENCH_"))
            self.assertIn(row["category"], {"baseline_real", "event_scaling", "batch_size_ablation", "verification_ablation"})
            self.assertGreater(int(row["event_count"]), 0)
            self.assertGreater(int(row["batch_size"]), 0)
            self.assertGreater(int(row["block_count"]), 0)
            self.assertGreater(int(row["repetitions"]), 0)
            self.assertGreater(float(row["mean_time_ms"]), 0.0)
            self.assertGreater(float(row["throughput_eps"]), 0.0)
            self.assertGreaterEqual(float(row["peak_memory_kb"]), 0.0)

    def test_06_benchmark_json_summary_schema(self) -> None:
        """Exported JSON summary must contain all required metadata, metrics, and disclaimers."""
        json_path = RESULTS_DIR / "phase5_performance_summary.json"
        self.assertTrue(json_path.is_file(), f"Missing JSON summary file: {json_path}")

        with open(json_path, mode="r", encoding="utf-8") as fp:
            data = json.load(fp)

        self.assertIn("benchmark_metadata", data)
        self.assertIn("baseline_real_workload_metrics", data)
        self.assertIn("ablation_findings", data)
        self.assertIn("security_and_distributed_systems_boundary", data)

        baseline = data["baseline_real_workload_metrics"]
        self.assertEqual(baseline["total_events"], 25)
        self.assertEqual(baseline["batch_size"], 5)
        self.assertEqual(baseline["block_count"], 6)
        self.assertGreater(baseline["full_verification_mean_ms"], 0.0)
        self.assertGreater(baseline["event_adaptation_mean_ms"], 0.0)

        ablation = data["ablation_findings"]
        ratio = ablation["verification_inclusion_proof_overhead_ratio"]
        self.assertGreater(ratio, 0.40)
        self.assertLess(ratio, 0.70)

        disclaimer = data["security_and_distributed_systems_boundary"]
        self.assertIn("single-node", disclaimer.lower())
        self.assertIn("distributed consensus", disclaimer.lower())

    def test_07_all_diagnostic_plots_exist_and_non_empty(self) -> None:
        """All three publication-quality diagnostic PNG plots must exist and be non-empty."""
        plot_names = [
            "phase5_scaling_event_count.png",
            "phase5_scaling_batch_size.png",
            "phase5_verification_ablation.png",
        ]
        for name in plot_names:
            p = RESULTS_DIR / name
            self.assertTrue(p.is_file(), f"Expected plot file missing: {p}")
            self.assertGreater(p.stat().st_size, 10000, f"Plot file {p} is suspiciously small")

    def test_08_part4_report_files_remain_unchanged(self) -> None:
        """Part 4 artifacts must remain completely intact and unmodified."""
        p4_baseline = RESULTS_DIR / "phase5_baseline_ledger.json"
        p4_report = RESULTS_DIR / "phase5_tamper_detection_report.csv"
        p4_summary = RESULTS_DIR / "phase5_tamper_detection_summary.json"

        self.assertTrue(p4_baseline.is_file())
        self.assertTrue(p4_report.is_file())
        self.assertTrue(p4_summary.is_file())

        # Verify baseline ledger loads cleanly and verifies
        ledger = BlockchainLedger.load_from_json(p4_baseline)
        verifier = ChainVerifier()
        res = verifier.verify_ledger(ledger)
        self.assertTrue(res.is_valid, f"Part 4 baseline ledger verification failed: {res.errors}")
        self.assertEqual(ledger.total_event_count, 25)
        self.assertEqual(ledger.block_count, 6)


if __name__ == "__main__":
    unittest.main()
