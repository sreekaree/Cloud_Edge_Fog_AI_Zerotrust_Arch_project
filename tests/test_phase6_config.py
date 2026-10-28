"""MedTrustEdge Phase 6 — Configuration Unit Tests.

Validates centralized YAML configuration parsing, boundary validation,
error handling for invalid values, and default backward compatibility.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from src.blockchain.config import (
    BlockchainConfig,
    CheckpointConfig,
    ConfigValidationError,
    LedgerConfig,
    load_blockchain_config,
)

BASE_DIR = Path(__file__).resolve().parent.parent


class TestPhase6Config(unittest.TestCase):
    """Test suite for Phase 6 centralized blockchain configuration."""

    def test_01_default_config_loading(self) -> None:
        """Default configuration must supply sensible Phase 5 compatible values."""
        cfg = BlockchainConfig()
        cfg.validate()
        self.assertEqual(cfg.version, "1.0")
        self.assertEqual(cfg.ledger.batch_size, 5)
        self.assertEqual(cfg.ledger.duplicate_policy, "REJECT")
        self.assertTrue(cfg.verification.verify_merkle_roots)
        self.assertTrue(cfg.checkpoint.enabled)

    def test_02_yaml_file_loading(self) -> None:
        """Loading config/blockchain_config.yaml must succeed and match expected attributes."""
        cfg_path = BASE_DIR / "config" / "blockchain_config.yaml"
        self.assertTrue(cfg_path.is_file(), f"Config file missing at {cfg_path}")
        cfg = load_blockchain_config(cfg_path)
        self.assertEqual(cfg.version, "1.0")
        self.assertEqual(cfg.ledger.batch_size, 5)
        self.assertEqual(cfg.checkpoint.algorithm, "Ed25519")
        self.assertIn(25, cfg.benchmarking.scaling_event_counts)

    def test_03_invalid_batch_size_rejection(self) -> None:
        """Negative test: Non-positive or non-integer batch_size must raise ConfigValidationError."""
        with self.assertRaises(ConfigValidationError):
            LedgerConfig(batch_size=0).validate()
        with self.assertRaises(ConfigValidationError):
            LedgerConfig(batch_size=-5).validate()

    def test_04_invalid_duplicate_policy_rejection(self) -> None:
        """Negative test: Unsupported duplicate policy string must raise ConfigValidationError."""
        with self.assertRaises(ConfigValidationError):
            LedgerConfig(duplicate_policy="SILENT_IGNORE").validate()

    def test_05_invalid_algorithm_rejection(self) -> None:
        """Negative test: Unsupported signature algorithm must raise ConfigValidationError."""
        with self.assertRaises(ConfigValidationError):
            CheckpointConfig(algorithm="RSA-4096").validate()

    def test_06_to_dict_roundtrip_fidelity(self) -> None:
        """Config to_dict must produce complete mapping containing all subsystem sections."""
        cfg = load_blockchain_config()
        d = cfg.to_dict()
        required_keys = ["version", "ledger", "artifacts", "verification", "benchmarking", "checkpoint", "output"]
        for k in required_keys:
            self.assertIn(k, d)
        self.assertEqual(d["ledger"]["batch_size"], 5)


if __name__ == "__main__":
    unittest.main()
