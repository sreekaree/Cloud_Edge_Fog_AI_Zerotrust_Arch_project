"""Phase 3B: AI Anomaly Detection Model for IoMT Cloud-Fog-Edge Telemetry.

Builds leakage-free, reproducible anomaly detection models using pre-enforcement
observable features and domain network relations, evaluated via Stratified K-Fold CV.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

CATEGORICAL_FEATURES = ["tenant_id", "source_device", "destination", "service"]
NUMERICAL_FEATURES = [
    "port",
    "connection_frequency_60s",
    "is_cross_tenant",
    "is_diagnostic_service",
]


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract strictly pre-enforcement observable request features and domain relations.

    Excludes all post-enforcement artifacts (packet loss, timeout durations, iptables drops)
    and policy engine decisions to guarantee zero label leakage.
    """
    feat = pd.DataFrame(index=df.index)
    feat["tenant_id"] = df["tenant_id"].astype(str)
    feat["source_device"] = df["source_device"].astype(str)
    feat["destination"] = df["destination"].astype(str)
    feat["service"] = df["service"].astype(str)
    feat["port"] = df["port"].astype(float)
    feat["connection_frequency_60s"] = df["connection_frequency_60s"].astype(float)

    # Engineered domain relations:
    # 1. Cross-tenant request: originating tenant mismatch with target resource tenant
    dest_str = df["destination"].astype(str)
    tenant_a_cross = (df["tenant_id"] == "A") & dest_str.str.endswith("_b")
    tenant_b_cross = (df["tenant_id"] == "B") & dest_str.str.endswith("_a")
    feat["is_cross_tenant"] = (tenant_a_cross | tenant_b_cross).astype(float)

    # 2. Diagnostic/Management service request on non-telemetry ports
    feat["is_diagnostic_service"] = (
        (df["service"] == "fog_diagnostic") | (df["port"] == 9555)
    ).astype(float)

    return feat


def create_preprocessor() -> ColumnTransformer:
    """Build column transformer with one-hot encoding and feature scaling."""
    return ColumnTransformer(
        transformers=[
            (
                "cat",
                OneHotEncoder(
                    drop="first",
                    sparse_output=False,
                    handle_unknown="ignore",
                ),
                CATEGORICAL_FEATURES,
            ),
            (
                "num",
                StandardScaler(),
                NUMERICAL_FEATURES,
            ),
        ]
    )


def initialize_models(config: dict[str, Any]) -> dict[str, Any]:
    """Instantiate candidate and baseline classifiers with fixed random seeds."""
    hp = config.get("hyperparameters", {})
    rf_hp = hp.get("random_forest", {"n_estimators": 100, "max_depth": 3, "class_weight": "balanced", "random_state": 42})
    dt_hp = hp.get("decision_tree", {"max_depth": 3, "class_weight": "balanced", "random_state": 42})
    lr_hp = hp.get("logistic_regression", {"max_iter": 500, "class_weight": "balanced", "random_state": 42})

    return {
        "RandomForest": RandomForestClassifier(**rf_hp),
        "DecisionTree": DecisionTreeClassifier(**dt_hp),
        "LogisticRegression": LogisticRegression(**lr_hp),
    }


def evaluate_models_cross_validation(
    df_features: pd.DataFrame,
    y: np.ndarray,
    models: dict[str, Any],
    n_splits: int = 5,
    random_state: int = 42,
) -> tuple[pd.DataFrame, dict[str, dict[str, np.ndarray]]]:
    """Perform Stratified K-Fold CV ensuring preprocessors are fit strictly on training folds."""
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    metrics_records = []
    oof_results: dict[str, dict[str, np.ndarray]] = {}

    for name, model in models.items():
        oof_preds = np.zeros(len(y), dtype=int)
        oof_probs = np.zeros(len(y), dtype=float)

        for train_idx, test_idx in skf.split(df_features, y):
            train_x_raw, test_x_raw = df_features.iloc[train_idx], df_features.iloc[test_idx]
            train_y, test_y = y[train_idx], y[test_idx]

            fold_preprocessor = create_preprocessor()
            train_x = fold_preprocessor.fit_transform(train_x_raw)
            test_x = fold_preprocessor.transform(test_x_raw)

            model.fit(train_x, train_y)
            oof_preds[test_idx] = model.predict(test_x)

            if hasattr(model, "predict_proba"):
                oof_probs[test_idx] = model.predict_proba(test_x)[:, 1]
            else:
                oof_probs[test_idx] = oof_preds[test_idx]

        acc = float(accuracy_score(y, oof_preds))
        prec = float(precision_score(y, oof_preds, zero_division=0))
        rec = float(recall_score(y, oof_preds, zero_division=0))
        f1 = float(f1_score(y, oof_preds, zero_division=0))
        auc = float(roc_auc_score(y, oof_probs))
        cm = confusion_matrix(y, oof_preds)

        tn, fp, fn, tp = cm.ravel()
        metrics_records.append({
            "model": name,
            "evaluation_method": f"stratified_{n_splits}_fold_cv",
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        })

        oof_results[name] = {
            "preds": oof_preds,
            "probs": oof_probs,
        }

    return pd.DataFrame(metrics_records), oof_results


def fit_final_model(
    df_features: pd.DataFrame,
    y: np.ndarray,
    model: Any,
) -> tuple[Any, ColumnTransformer, list[str], pd.DataFrame, np.ndarray]:
    """Fit final model on full dataset to extract feature importances and continuous anomaly scores."""
    preprocessor = create_preprocessor()
    x_trans = preprocessor.fit_transform(df_features)
    feature_names = list(preprocessor.get_feature_names_out())

    model.fit(x_trans, y)
    probs = model.predict_proba(x_trans)[:, 1] if hasattr(model, "predict_proba") else model.predict(x_trans)

    # Extract importance / coefficients
    importance_records = []
    if hasattr(model, "feature_importances_"):
        for fname, imp in zip(feature_names, model.feature_importances_):
            importance_records.append({"feature": fname, "importance": round(float(imp), 6)})
    elif hasattr(model, "coef_"):
        for fname, coef in zip(feature_names, model.coef_[0]):
            importance_records.append({"feature": fname, "importance": round(float(abs(coef)), 6)})

    importance_df = pd.DataFrame(importance_records).sort_values(by="importance", ascending=False)
    return model, preprocessor, feature_names, importance_df, probs


def sha256_file(path: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()
