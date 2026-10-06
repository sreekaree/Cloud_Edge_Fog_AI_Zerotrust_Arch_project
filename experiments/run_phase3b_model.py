"""Phase 3B Experiment Runner: Train and evaluate AI Anomaly Detection Models."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ai.anomaly_model import (
    engineer_features,
    evaluate_models_cross_validation,
    fit_final_model,
    initialize_models,
    sha256_file,
)

CONFIG_PATH = ROOT / "config" / "ai_model_config.yaml"
OUTPUT_DIR = ROOT / "results" / "ai"
PLOTS_DIR = ROOT / "plots" / "ai"


def plot_model_comparison(metrics_df: pd.DataFrame, output_path: Path) -> None:
    """Generate model comparison bar chart across cross-validation metrics."""
    plt.figure(figsize=(9, 5))
    metrics_to_plot = ["accuracy", "precision", "recall", "f1_score", "roc_auc"]
    models = metrics_df["model"].tolist()
    
    x = np.arange(len(metrics_to_plot))
    width = 0.25
    colors = ["#2b5c8f", "#d95f02", "#7570b3"]

    for i, model in enumerate(models):
        row = metrics_df[metrics_df["model"] == model].iloc[0]
        vals = [row[m] for m in metrics_to_plot]
        plt.bar(x + i * width, vals, width, label=model, color=colors[i % len(colors)], alpha=0.85)

    plt.ylabel("Score", fontsize=11)
    plt.title("Phase 3B: Cross-Validation Metrics Comparison (Stratified 5-Fold)", fontsize=12)
    plt.xticks(x + width, [m.replace("_", " ").title() for m in metrics_to_plot], fontsize=10)
    plt.ylim(0, 1.05)
    plt.grid(axis="y", linestyle="--", alpha=0.4)
    plt.legend(frameon=True)
    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150)
    plt.close()


def plot_confusion_matrix(cm: np.ndarray, model_name: str, output_path: Path) -> None:
    """Generate confusion matrix plot for primary model."""
    plt.figure(figsize=(5, 4.5))
    plt.imshow(cm, interpolation="nearest", cmap="Blues")
    plt.title(f"Confusion Matrix: {model_name} (Out-of-Fold)", fontsize=11)
    plt.colorbar()
    tick_marks = np.arange(2)
    classes = ["Normal", "Anomalous"]
    plt.xticks(tick_marks, classes, fontsize=10)
    plt.yticks(tick_marks, classes, fontsize=10)

    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(
                j, i, format(cm[i, j], "d"),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=13, weight="bold",
            )

    plt.ylabel("Ground Truth", fontsize=11)
    plt.xlabel("Predicted Label", fontsize=11)
    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150)
    plt.close()


def plot_feature_importance(importance_df: pd.DataFrame, output_path: Path) -> None:
    """Generate feature importance horizontal bar chart."""
    plt.figure(figsize=(8, 5))
    top_df = importance_df.head(10).iloc[::-1]
    
    clean_labels = [
        f.replace("cat__", "").replace("num__", "").replace("_", " ").title()
        for f in top_df["feature"]
    ]
    plt.barh(clean_labels, top_df["importance"], color="#1f77b4", alpha=0.85)
    plt.xlabel("Feature Importance (Gini Impurity Reduction)", fontsize=11)
    plt.title("Phase 3B: Top 10 Feature Importances (Random Forest)", fontsize=12)
    plt.grid(axis="x", linestyle="--", alpha=0.4)
    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150)
    plt.close()


def plot_anomaly_scores(preds_df: pd.DataFrame, output_path: Path) -> None:
    """Plot distribution of continuous anomaly scores across all scenarios."""
    plt.figure(figsize=(10, 5.5))
    scenarios = preds_df["scenario"].unique()
    scenario_order = sorted(scenarios, key=lambda s: preds_df[preds_df["scenario"] == s]["anomaly_score_full"].mean())
    
    means = [preds_df[preds_df["scenario"] == s]["anomaly_score_full"].mean() for s in scenario_order]
    labels = [preds_df[preds_df["scenario"] == s]["ground_truth_label"].iloc[0] for s in scenario_order]
    colors = ["#d95f02" if l == "anomalous" else "#2b5c8f" for l in labels]

    plt.barh(scenario_order, means, color=colors, alpha=0.85)
    plt.axvline(0.5, color="red", linestyle="--", alpha=0.7, label="Default Decision Threshold (0.5)")
    plt.xlabel("Mean Anomaly Score / Risk Probability [0.0, 1.0]", fontsize=11)
    plt.title("Continuous Anomaly Scores Across Controlled Scenarios (Phase 3B)", fontsize=12)
    plt.xlim(0, 1.05)
    plt.grid(axis="x", linestyle="--", alpha=0.4)
    
    # Custom legend
    import matplotlib.patches as mpatches
    norm_patch = mpatches.Patch(color="#2b5c8f", label="Ground Truth: Normal")
    anom_patch = mpatches.Patch(color="#d95f02", label="Ground Truth: Anomalous")
    thresh_line = plt.Line2D([0], [0], color="red", linestyle="--", label="Threshold (0.5)")
    plt.legend(handles=[norm_patch, anom_patch, thresh_line], loc="lower right", frameon=True)
    
    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=150)
    plt.close()


def main():
    print("=== Phase 3B: AI Anomaly Detection Model Pipeline ===")
    config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    dataset_path = ROOT / config["data"]["dataset_path"]
    
    if not dataset_path.exists():
        raise SystemExit(f"Dataset missing: {dataset_path}")

    current_hash = sha256_file(dataset_path)
    manifest_path = ROOT / config["data"]["manifest_path"]
    if manifest_path.exists():
        expected_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if current_hash != expected_manifest.get("dataset_sha256"):
            raise SystemExit(f"Dataset integrity mismatch! Expected {expected_manifest.get('dataset_sha256')}, got {current_hash}")
        print(f"Verified dataset integrity (SHA-256: {current_hash[:16]}...)")

    df = pd.read_csv(dataset_path)
    print(f"Dataset loaded: {len(df)} records across {len(df.columns)} fields")
    
    # Target definition
    y = (df[config["data"]["target_column"]] == config["data"]["positive_class"]).astype(int).to_numpy()
    
    # Leakage-free feature engineering
    df_features = engineer_features(df)
    print(f"Engineered features ready: {list(df_features.columns)}")

    # Initialize candidate and baseline models
    models = initialize_models(config)
    print(f"Candidate models initialized: {list(models.keys())}")

    # Evaluate all models via Stratified 5-Fold Cross-Validation
    n_splits = config["evaluation"]["n_splits"]
    metrics_df, oof_results = evaluate_models_cross_validation(
        df_features, y, models, n_splits=n_splits, random_state=config["model"]["random_seed"]
    )
    print("\n--- Cross-Validation Evaluation (Stratified 5-Fold) ---")
    print(metrics_df[["model", "accuracy", "precision", "recall", "f1_score", "roc_auc"]].to_string(index=False))

    # Save metrics CSV
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    metrics_csv_path = OUTPUT_DIR / "phase3b_model_metrics.csv"
    metrics_df.to_csv(metrics_csv_path, index=False)
    print(f"\nSaved metrics to {metrics_csv_path}")

    # Primary candidate model fit (Random Forest)
    primary_name = "RandomForest"
    primary_model = models[primary_name]
    fitted_model, preprocessor, feature_names, importance_df, full_probs = fit_final_model(
        df_features, y, primary_model
    )

    # Save feature importances CSV
    importance_csv_path = OUTPUT_DIR / "phase3b_feature_importance.csv"
    importance_df.to_csv(importance_csv_path, index=False)
    print(f"Saved feature importances to {importance_csv_path}")

    # Out-of-fold and full anomaly scores
    oof_preds = oof_results[primary_name]["preds"]
    oof_probs = oof_results[primary_name]["probs"]

    predictions_df = pd.DataFrame({
        "record_id": df["record_id"],
        "scenario": df["scenario"],
        "source_device": df["source_device"],
        "tenant_id": df["tenant_id"],
        "destination": df["destination"],
        "service": df["service"],
        "port": df["port"],
        "connection_frequency_60s": df["connection_frequency_60s"],
        "ground_truth_label": df["label"],
        "predicted_label_oof": ["anomalous" if p == 1 else "normal" for p in oof_preds],
        "anomaly_score_oof": np.round(oof_probs, 6),
        "anomaly_score_full": np.round(full_probs, 6),
    })
    predictions_csv_path = OUTPUT_DIR / "phase3b_predictions.csv"
    predictions_df.to_csv(predictions_csv_path, index=False)
    print(f"Saved predictions to {predictions_csv_path}")

    # Model Manifest JSON
    manifest = {
        "model_version": config["model"]["version"],
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_file": str(dataset_path.name),
        "dataset_sha256": current_hash,
        "primary_model": primary_name,
        "candidate_models": list(models.keys()),
        "evaluation_method": f"stratified_{n_splits}_fold_cross_validation",
        "random_seed": config["model"]["random_seed"],
        "features": {
            "observable_request_features": config["features"]["observable_request_features"],
            "engineered_domain_features": config["features"]["engineered_domain_features"],
            "one_hot_encoded_dim": len(feature_names),
            "encoded_feature_names": feature_names,
        },
        "leakage_controls": {
            "excluded_post_enforcement_artifacts": list(config["features"]["excluded_leakage_features"].keys()),
            "excluded_identifiers": list(config["features"]["excluded_identifiers"].keys()),
        },
        "metrics_summary": metrics_df.to_dict(orient="records"),
        "top_features": importance_df.head(5).to_dict(orient="records"),
    }
    manifest_path = OUTPUT_DIR / "phase3b_model_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Saved model manifest to {manifest_path}")

    # Generate plots
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    plot_model_comparison(metrics_df, PLOTS_DIR / "model_comparison.png")
    
    rf_row = metrics_df[metrics_df["model"] == primary_name].iloc[0]
    cm = np.array([
        [rf_row["true_negatives"], rf_row["false_positives"]],
        [rf_row["false_negatives"], rf_row["true_positives"]],
    ])
    plot_confusion_matrix(cm, primary_name, PLOTS_DIR / "confusion_matrix.png")
    plot_feature_importance(importance_df, PLOTS_DIR / "feature_importance.png")
    plot_anomaly_scores(predictions_df, PLOTS_DIR / "anomaly_scores_by_scenario.png")
    print(f"Saved plots to {PLOTS_DIR}")
    print("\nPhase 3B execution complete.")


if __name__ == "__main__":
    main()
