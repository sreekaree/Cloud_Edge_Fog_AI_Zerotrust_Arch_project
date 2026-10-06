"""Unit tests for Phase 3B AI Anomaly Detection Model."""
from pathlib import Path
import unittest

import numpy as np
import pandas as pd
import yaml

from src.ai.anomaly_model import (
    CATEGORICAL_FEATURES,
    NUMERICAL_FEATURES,
    create_preprocessor,
    engineer_features,
    evaluate_models_cross_validation,
    fit_final_model,
    initialize_models,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "ai_model_config.yaml"
DATASET_PATH = ROOT / "results" / "ai" / "phase3a_iomt_anomaly_dataset.csv"


class AiAnomalyModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
        cls.df = pd.read_csv(DATASET_PATH)

    def test_feature_engineering_excludes_leakage(self):
        """Engineered features must strictly exclude all post-enforcement fields and decisions."""
        feat = engineer_features(self.df)
        prohibited = [
            "decision",
            "enforcement",
            "scenario",
            "experiment_id",
            "label",
            "label_basis",
            "packet_loss_percent",
            "network_rtt_ms",
            "flow_duration_ms",
            "flow_rate_pps",
            "policy_decision_latency_ms",
            "trust_state",
            "record_id",
            "timestamp_utc",
        ]
        for col in prohibited:
            self.assertNotIn(col, feat.columns, f"Prohibited leakage column found: {col}")

    def test_feature_engineering_cross_tenant_detection(self):
        """Cross-tenant requests must be deterministically flagged by subnet/boundary."""
        sample_cross = pd.DataFrame([{
            "tenant_id": "A",
            "source_device": "iotA1",
            "destination": "edge_b",
            "service": "edge_telemetry",
            "port": 8443,
            "connection_frequency_60s": 1,
        }])
        sample_same = pd.DataFrame([{
            "tenant_id": "A",
            "source_device": "iotA1",
            "destination": "edge_a",
            "service": "edge_telemetry",
            "port": 8443,
            "connection_frequency_60s": 1,
        }])
        feat_cross = engineer_features(sample_cross)
        feat_same = engineer_features(sample_same)
        self.assertEqual(feat_cross["is_cross_tenant"].iloc[0], 1.0)
        self.assertEqual(feat_same["is_cross_tenant"].iloc[0], 0.0)

    def test_feature_engineering_diagnostic_service_flag(self):
        """Requests to diagnostic services or non-telemetry ports must be flagged."""
        diag_sample = pd.DataFrame([{
            "tenant_id": "A",
            "source_device": "iotA2",
            "destination": "fog_a_diagnostic",
            "service": "fog_diagnostic",
            "port": 9555,
            "connection_frequency_60s": 1,
        }])
        telemetry_sample = pd.DataFrame([{
            "tenant_id": "A",
            "source_device": "iotA2",
            "destination": "fog_a",
            "service": "fog_telemetry",
            "port": 9443,
            "connection_frequency_60s": 1,
        }])
        self.assertEqual(engineer_features(diag_sample)["is_diagnostic_service"].iloc[0], 1.0)
        self.assertEqual(engineer_features(telemetry_sample)["is_diagnostic_service"].iloc[0], 0.0)

    def test_models_produce_continuous_probabilities(self):
        """Anomaly model must output continuous probability scores bounded in [0.0, 1.0]."""
        feat = engineer_features(self.df)
        y = (self.df["label"] == "anomalous").astype(int).to_numpy()
        models = initialize_models(self.config)

        model = models["RandomForest"]
        fitted_model, preprocessor, feature_names, importance_df, probs = fit_final_model(feat, y, model)
        
        self.assertEqual(len(probs), len(self.df))
        self.assertTrue(np.all((probs >= 0.0) & (probs <= 1.0)), "Probabilities must be in [0.0, 1.0]")
        self.assertTrue(len(np.unique(probs)) > 2, "Probabilities should be continuous, not purely binary")

    def test_stratified_k_fold_cross_validation_runs(self):
        """Cross-validation must evaluate all 25 samples out-of-fold and report valid metrics."""
        feat = engineer_features(self.df)
        y = (self.df["label"] == "anomalous").astype(int).to_numpy()
        models = initialize_models(self.config)

        metrics_df, oof_results = evaluate_models_cross_validation(
            feat, y, models, n_splits=5, random_state=42
        )

        self.assertEqual(len(metrics_df), 3)  # RandomForest, DecisionTree, LogisticRegression
        for _, row in metrics_df.iterrows():
            self.assertTrue(0.0 <= row["accuracy"] <= 1.0)
            self.assertTrue(0.0 <= row["roc_auc"] <= 1.0)
            self.assertEqual(row["true_negatives"] + row["false_positives"] + row["false_negatives"] + row["true_positives"], 25)

        for name in models:
            self.assertEqual(len(oof_results[name]["preds"]), 25)
            self.assertEqual(len(oof_results[name]["probs"]), 25)

    def test_feature_importance_validity(self):
        """Feature importances for tree models must sum approximately to 1.0."""
        feat = engineer_features(self.df)
        y = (self.df["label"] == "anomalous").astype(int).to_numpy()
        models = initialize_models(self.config)

        model = models["RandomForest"]
        _, _, _, importance_df, _ = fit_final_model(feat, y, model)

        self.assertFalse(importance_df.empty)
        total_importance = importance_df["importance"].sum()
        self.assertAlmostEqual(total_importance, 1.0, places=2)

    def test_reproducibility_with_fixed_seed(self):
        """Runs with identical seed must yield strictly identical out-of-fold probabilities."""
        feat = engineer_features(self.df)
        y = (self.df["label"] == "anomalous").astype(int).to_numpy()

        models1 = initialize_models(self.config)
        models2 = initialize_models(self.config)

        _, oof1 = evaluate_models_cross_validation(feat, y, models1, n_splits=5, random_state=42)
        _, oof2 = evaluate_models_cross_validation(feat, y, models2, n_splits=5, random_state=42)

        np.testing.assert_array_almost_equal(
            oof1["RandomForest"]["probs"],
            oof2["RandomForest"]["probs"],
        )


if __name__ == "__main__":
    unittest.main()
