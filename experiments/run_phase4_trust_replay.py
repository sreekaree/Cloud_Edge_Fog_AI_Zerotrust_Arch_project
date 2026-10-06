"""Phase 4 Dynamic Trust Scoring Replay Runner and Ablation Experiment.

Executes an offline chronological simulation of preserved Phase 2 Zero Trust audit events
modulated by frozen Phase 3B Out-Of-Fold (OOF) machine learning anomaly scores.
"""
import sys
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.zerotrust.dynamic_trust import DynamicTrustEngine, DynamicState

EVENTS_PATH = BASE_DIR / "results" / "zerotrust" / "zerotrust_security_events.csv"
PREDICTIONS_PATH = BASE_DIR / "results" / "ai" / "phase3b_predictions.csv"
OUTPUT_DIR = BASE_DIR / "results" / "phase4"
PLOTS_DIR = BASE_DIR / "plots" / "phase4"


def run_replay(enable_ai: bool = True) -> tuple[pd.DataFrame, dict[str, float]]:
    """Runs the chronological 25-event replay trace using strictly anomaly_score_oof."""
    events_df = pd.read_csv(EVENTS_PATH)
    preds_df = pd.read_csv(PREDICTIONS_PATH)

    if len(events_df) != 25 or len(preds_df) != 25:
        raise ValueError(f"Expected 25 events and predictions, got {len(events_df)} and {len(preds_df)}")

    # Enforce strictly out-of-fold score usage
    if "anomaly_score_oof" not in preds_df.columns:
        raise KeyError("Mandatory column 'anomaly_score_oof' missing from predictions CSV.")

    engine = DynamicTrustEngine(enable_ai=enable_ai)
    trace_rows = []

    for idx in range(len(events_df)):
        row_z = events_df.iloc[idx]
        row_a = preds_df.iloc[idx]

        dev = str(row_z["device_id"])
        if dev != str(row_a["source_device"]):
            raise ValueError(f"Device mismatch at index {idx}: {dev} vs {row_a['source_device']}")

        decision = str(row_z["decision"])
        reason = str(row_z["reason"])
        service = str(row_z["service"])
        oof_score = float(row_a["anomaly_score_oof"])
        rec_id = str(row_a["record_id"])
        scenario = str(row_z["scenario"])

        # Offline reconstruction of frozen Phase 2 JIT state (never derived from scenario)
        is_jit = (service == "fog_diagnostic" and decision == "ALLOW" and reason == "allowed")

        res = engine.update(
            device_id=dev,
            decision=decision,
            reason=reason,
            oof_score=oof_score,
            is_jit=is_jit,
            service=service,
        )

        jit_str = "Active" if is_jit else "Inactive"
        trace_rows.append({
            "event_index": idx,
            "record_id": rec_id,
            "source_device": dev,
            "scenario": scenario,
            "p2_decision": decision,
            "p2_reason": reason,
            "jit_status": jit_str,
            "severity": res["severity"],
            "oof_score": round(oof_score, 4),
            "p_det": round(res["p_det"], 2),
            "p_ai": round(res["p_ai"], 2),
            "p_total": round(res["p_total"], 2),
            "rec": round(res["rec"], 2),
            "trust_before": round(res["trust_before"], 2),
            "trust_after": round(res["trust_after"], 2),
            "state_before": res["state_before"],
            "state_after": res["state_after"],
            "mapped_phase2_state": res["mapped_phase2_state"],
            "n_viol_before": res["n_viol_before"],
            "n_viol_after": res["n_viol_after"],
            "action_taken": res["action_taken"],
        })

    trace_df = pd.DataFrame(trace_rows)
    final_scores = {d: round(engine.get_score(d), 2) for d in sorted(engine.scores)}
    return trace_df, final_scores


def plot_trajectories(trace_df: pd.DataFrame, output_path: Path) -> None:
    """Plots dynamic trust score trajectories over the chronological 25-event sequence."""
    plt.figure(figsize=(11, 6), dpi=300)

    devices = ["iotA1", "iotA2", "iotA3", "iotB1", "iotB2", "iotB3"]
    colors = {
        "iotA1": "#D9381E",
        "iotA2": "#E67E22",
        "iotA3": "#27AE60",
        "iotB1": "#2980B9",
        "iotB2": "#8E44AD",
        "iotB3": "#16A085",
    }

    # Track trajectories chronologically per device
    for dev in devices:
        x_pts = []
        y_pts = []
        # Initial point before first event
        for _, r in trace_df.iterrows():
            if r["source_device"] == dev:
                if not x_pts:
                    x_pts.append(max(0, r["event_index"] - 0.5))
                    y_pts.append(r["trust_before"])
                x_pts.append(r["event_index"])
                y_pts.append(r["trust_after"])

        if x_pts:
            plt.plot(
                x_pts,
                y_pts,
                marker="o",
                linewidth=2.2,
                label=f"{dev} ({trace_df[trace_df['source_device']==dev]['state_after'].iloc[-1]})",
                color=colors[dev],
            )

    # Threshold guidelines
    plt.axhline(70.0, color="#E67E22", linestyle="--", linewidth=1.5, alpha=0.8, label="Trusted Floor (T=70)")
    plt.axhline(30.0, color="#C0392B", linestyle="--", linewidth=1.5, alpha=0.8, label="Revocation Threshold (T=30)")

    plt.title("MedTrustEdge Phase 4: Dynamic Trust Score Trajectories Across Audit Replay", fontsize=12, pad=12)
    plt.xlabel("Chronological Audit Event Index", fontsize=10)
    plt.ylabel("Dynamic Trust Score (T ∈ [0, 100])", fontsize=10)
    plt.ylim(-5, 105)
    plt.xlim(-0.5, 24.5)
    plt.xticks(range(0, 25, 2))
    plt.grid(True, linestyle=":", alpha=0.6)
    plt.legend(loc="lower left", fontsize=9, framealpha=0.95)
    plt.tight_layout()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path)
    plt.close()


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    print("================================================================================")
    print("MEDTRUSTEDGE PHASE 4: AI-DRIVEN DYNAMIC TRUST SCORING REPLAY")
    print("================================================================================")

    # 1. Hybrid Mode Replay
    trace_hybrid, final_hybrid = run_replay(enable_ai=True)
    trace_path = OUTPUT_DIR / "phase4_trust_trace.csv"
    trace_hybrid.to_csv(trace_path, index=False)
    print(f"Hybrid replay trace successfully written to: {trace_path}")

    # 2. Deterministic-Only Ablation Arm
    trace_det, final_det = run_replay(enable_ai=False)

    # 3. Compile Ablation Metrics
    ablation_records = []
    all_devs = sorted(final_hybrid.keys())
    for d in all_devs:
        sub_h = trace_hybrid[trace_hybrid["source_device"] == d]
        sub_d = trace_det[trace_det["source_device"] == d]
        ablation_records.append({
            "device_id": d,
            "final_score_hybrid": final_hybrid[d],
            "final_score_det_only": final_det[d],
            "final_state_hybrid": sub_h["state_after"].iloc[-1],
            "final_state_det_only": sub_d["state_after"].iloc[-1],
            "score_delta": round(final_hybrid[d] - final_det[d], 2),
            "state_match": (sub_h["state_after"].iloc[-1] == sub_d["state_after"].iloc[-1]),
            "cum_det_penalty_hybrid": round(sub_h["p_det"].sum(), 2),
            "cum_ai_penalty_hybrid": round(sub_h["p_ai"].sum(), 2),
            "cum_recovery_hybrid": round(sub_h["rec"].sum(), 2),
            "cum_det_penalty_det_only": round(sub_d["p_det"].sum(), 2),
            "cum_ai_penalty_det_only": 0.0,
            "cum_recovery_det_only": round(sub_d["rec"].sum(), 2),
        })

    ablation_df = pd.DataFrame(ablation_records)
    ablation_path = OUTPUT_DIR / "phase4_ablation_metrics.csv"
    ablation_df.to_csv(ablation_path, index=False)
    print(f"Ablation metrics successfully written to: {ablation_path}")

    # 4. Generate Trajectory Plot
    plot_path = PLOTS_DIR / "phase4_trust_trajectories.png"
    plot_trajectories(trace_hybrid, plot_path)
    print(f"Trust trajectory plot successfully saved to: {plot_path}")

    # 5. Display Summary
    print("\n--- Final Device Status Summary (Hybrid Mode) ---")
    for d in all_devs:
        sub = trace_hybrid[trace_hybrid["source_device"] == d]
        print(f"  {d}: Score = {final_hybrid[d]:6.2f} | State = {sub['state_after'].iloc[-1]:10s} | N_viol = {sub['n_viol_after'].iloc[-1]}")

    print("\n--- Ablation Comparison (Hybrid vs Deterministic-Only) ---")
    print(ablation_df[["device_id", "final_score_hybrid", "final_score_det_only", "final_state_hybrid", "final_state_det_only", "score_delta", "state_match"]].to_string(index=False))

    print("\nPhase 4 offline replay and ablation complete.")


if __name__ == "__main__":
    main()
