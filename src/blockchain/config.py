"""MedTrustEdge Phase 6 — Centralized Blockchain Configuration Engine.

Loads, validates, and serves configuration parameters for the blockchain subsystem,
governing ledger batching, event adapter policies, verification flags, benchmark
parameters, cryptographic checkpointing, and output directory isolation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import os
from pathlib import Path
from typing import Any, Union
import yaml


class ConfigValidationError(ValueError):
    """Raised when blockchain configuration values violate schema or boundary rules."""
    pass


@dataclass(frozen=True)
class LedgerConfig:
    batch_size: int = 5
    schema_version: str = "1.0"
    genesis_previous_hash: str = "0" * 64
    duplicate_policy: str = "REJECT"

    def validate(self) -> None:
        if not isinstance(self.batch_size, int) or self.batch_size < 1:
            raise ConfigValidationError(f"ledger.batch_size must be positive integer, got: {self.batch_size}")
        if self.duplicate_policy not in {"REJECT", "WARN_AND_SKIP"}:
            raise ConfigValidationError(
                f"ledger.duplicate_policy must be 'REJECT' or 'WARN_AND_SKIP', got: {self.duplicate_policy}"
            )
        if len(self.genesis_previous_hash) != 64:
            raise ConfigValidationError("ledger.genesis_previous_hash must be exactly 64 hex characters")


@dataclass(frozen=True)
class ArtifactsConfig:
    phase4_trust_trace_path: str = "results/phase4/phase4_trust_trace.csv"
    phase2_security_events_path: str = "results/zerotrust/zerotrust_security_events.csv"
    phase3a_dataset_path: str = "results/ai/phase3a_iomt_anomaly_dataset.csv"
    phase3b_predictions_path: str = "results/ai/phase3b_predictions.csv"
    phase5_baseline_ledger_path: str = "results/phase5/phase5_baseline_ledger.json"

    def validate(self) -> None:
        for name, val in [
            ("phase4_trust_trace_path", self.phase4_trust_trace_path),
            ("phase2_security_events_path", self.phase2_security_events_path),
            ("phase5_baseline_ledger_path", self.phase5_baseline_ledger_path),
        ]:
            if not isinstance(val, str) or not val.strip():
                raise ConfigValidationError(f"artifacts.{name} must be non-empty string path")


@dataclass(frozen=True)
class VerificationConfig:
    verify_merkle_roots: bool = True
    verify_inclusion_proofs: bool = True
    verify_header_continuity: bool = True
    verify_timestamps_monotonic: bool = True
    verify_payload_hashes: bool = True

    def validate(self) -> None:
        for f in [
            "verify_merkle_roots",
            "verify_inclusion_proofs",
            "verify_header_continuity",
            "verify_timestamps_monotonic",
            "verify_payload_hashes",
        ]:
            if not isinstance(getattr(self, f), bool):
                raise ConfigValidationError(f"verification.{f} must be boolean")


@dataclass(frozen=True)
class BenchmarkConfig:
    baseline_repetitions: int = 30
    synthetic_small_repetitions: int = 20
    synthetic_large_repetitions: int = 10
    scaling_event_counts: list[int] = field(default_factory=lambda: [25, 50, 100, 250, 500, 1000])
    ablation_batch_sizes: list[int] = field(default_factory=lambda: [1, 2, 5, 10, 25, 50])

    def validate(self) -> None:
        for name, r in [
            ("baseline_repetitions", self.baseline_repetitions),
            ("synthetic_small_repetitions", self.synthetic_small_repetitions),
            ("synthetic_large_repetitions", self.synthetic_large_repetitions),
        ]:
            if not isinstance(r, int) or r < 1:
                raise ConfigValidationError(f"benchmarking.{name} must be integer >= 1, got: {r}")
        if not self.scaling_event_counts or any(not isinstance(x, int) or x < 1 for x in self.scaling_event_counts):
            raise ConfigValidationError("benchmarking.scaling_event_counts must be non-empty list of positive ints")
        if not self.ablation_batch_sizes or any(not isinstance(x, int) or x < 1 for x in self.ablation_batch_sizes):
            raise ConfigValidationError("benchmarking.ablation_batch_sizes must be non-empty list of positive ints")


@dataclass(frozen=True)
class CheckpointConfig:
    enabled: bool = True
    algorithm: str = "Ed25519"
    key_id: str = "edge-gateway-alpha-01"
    key_env_var: str = "MEDTRUST_CHECKPOINT_KEY"
    pubkey_env_var: str = "MEDTRUST_CHECKPOINT_PUBKEY"
    external_notary_url: str = ""

    def validate(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ConfigValidationError("checkpoint.enabled must be boolean")
        if self.algorithm not in {"Ed25519", "HMAC-SHA256"}:
            raise ConfigValidationError(f"checkpoint.algorithm must be 'Ed25519' or 'HMAC-SHA256', got: {self.algorithm}")
        if not isinstance(self.key_id, str) or not self.key_id.strip():
            raise ConfigValidationError("checkpoint.key_id must be non-empty string")


@dataclass(frozen=True)
class OutputConfig:
    base_dir: str = "results/phase6"
    per_run_dir_prefix: str = "run_"

    def validate(self) -> None:
        if not isinstance(self.base_dir, str) or not self.base_dir.strip():
            raise ConfigValidationError("output.base_dir must be non-empty string")
        if not isinstance(self.per_run_dir_prefix, str):
            raise ConfigValidationError("output.per_run_dir_prefix must be string")


@dataclass(frozen=True)
class BlockchainConfig:
    version: str = "1.0"
    ledger: LedgerConfig = field(default_factory=LedgerConfig)
    artifacts: ArtifactsConfig = field(default_factory=ArtifactsConfig)
    verification: VerificationConfig = field(default_factory=VerificationConfig)
    benchmarking: BenchmarkConfig = field(default_factory=BenchmarkConfig)
    checkpoint: CheckpointConfig = field(default_factory=CheckpointConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    def validate(self) -> None:
        if not isinstance(self.version, str) or not self.version.strip():
            raise ConfigValidationError("version must be non-empty string")
        self.ledger.validate()
        self.artifacts.validate()
        self.verification.validate()
        self.benchmarking.validate()
        self.checkpoint.validate()
        self.output.validate()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_blockchain_config(config_path: Union[str, Path, None] = None) -> BlockchainConfig:
    """Loads and validates blockchain configuration from a YAML file.

    If config_path is None, attempts to resolve 'config/blockchain_config.yaml'.
    If the file does not exist, returns safe default configuration (Phase 5 compatible).
    Raises ConfigValidationError if configuration fails validation.
    """
    if config_path is None:
        # Search relative to repo root
        repo_root = Path(__file__).resolve().parent.parent.parent
        target_path = repo_root / "config" / "blockchain_config.yaml"
    else:
        target_path = Path(config_path)

    if not target_path.exists():
        # Fall back to sensible Phase 5 defaults
        cfg = BlockchainConfig()
        cfg.validate()
        return cfg

    try:
        with open(target_path, mode="r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp) or {}
    except Exception as exc:
        raise ConfigValidationError(f"Failed to parse YAML file at {target_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigValidationError(f"YAML configuration at {target_path} must be a dictionary/mapping")

    ledger_data = data.get("ledger", {})
    artifacts_data = data.get("artifacts", {})
    verification_data = data.get("verification", {})
    bench_data = data.get("benchmarking", {})
    checkpoint_data = data.get("checkpoint", {})
    output_data = data.get("output", {})

    cfg = BlockchainConfig(
        version=str(data.get("version", "1.0")),
        ledger=LedgerConfig(**ledger_data) if isinstance(ledger_data, dict) else LedgerConfig(),
        artifacts=ArtifactsConfig(**artifacts_data) if isinstance(artifacts_data, dict) else ArtifactsConfig(),
        verification=VerificationConfig(**verification_data) if isinstance(verification_data, dict) else VerificationConfig(),
        benchmarking=BenchmarkConfig(**bench_data) if isinstance(bench_data, dict) else BenchmarkConfig(),
        checkpoint=CheckpointConfig(**checkpoint_data) if isinstance(checkpoint_data, dict) else CheckpointConfig(),
        output=OutputConfig(**output_data) if isinstance(output_data, dict) else OutputConfig(),
    )
    cfg.validate()
    return cfg
