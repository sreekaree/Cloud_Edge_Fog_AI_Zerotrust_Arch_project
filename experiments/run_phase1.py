"""Run MedTrustEdge Phase 1 experiments from the repository root."""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.experiments.latency_experiment import run_phase1_experiments
from src.topology.healthcare_topology import load_topology
from src.utils.metrics import summarize


def make_plots(experiments: dict, plot_dir: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plot_dir.mkdir(parents=True, exist_ok=True)
    groups = ("edge_latency", "fog_latency", "end_to_end_latency")
    plt.figure(figsize=(8, 4.5))
    plt.bar(["Edge", "Fog", "Cloud"], [summarize(experiments[key])["mean_latency_ms"] for key in groups], color=["#2a9d8f", "#e9c46a", "#e76f51"])
    plt.ylabel("Mean latency (ms)"); plt.title("MedTrustEdge Phase 1 latency by destination"); plt.tight_layout()
    plt.savefig(plot_dir / "latency_by_layer.png", dpi=150); plt.close()
    plt.figure(figsize=(6, 4.5))
    comparison = experiments["baseline_comparison"]
    distributed = [r["latency_ms"] for r in comparison if r["destination"] == "edge_fog_cloud"]
    baseline = [r["latency_ms"] for r in comparison if r["destination"] == "cloud_only"]
    plt.bar(["Edge-Fog-Cloud", "Cloud-only"], [sum(distributed)/len(distributed), sum(baseline)/len(baseline)], color=["#457b9d", "#f4a261"])
    plt.ylabel("Mean latency (ms)"); plt.title("Configured path comparison"); plt.tight_layout()
    plt.savefig(plot_dir / "baseline_comparison.png", dpi=150); plt.close()
    plt.figure(figsize=(8, 4.5))
    plt.bar(["Edge", "Fog", "Cloud", "Cloud-only"], [summarize(experiments[key])["mean_throughput_mbps"] for key in (*groups, "cloud_latency")], color="#6d597a")
    plt.ylabel("Mean effective throughput (Mbps)"); plt.title("Packet throughput by experiment"); plt.tight_layout()
    plt.savefig(plot_dir / "throughput.png", dpi=150); plt.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=ROOT / "config" / "network_config.yaml", type=Path)
    parser.add_argument("--results-dir", default=ROOT / "results" / "fallback", type=Path)
    parser.add_argument("--plots-dir", default=ROOT / "plots", type=Path)
    args = parser.parse_args()
    topology = load_topology(args.config)
    problems = topology.validate()
    if problems:
        raise SystemExit("Topology validation failed: " + "; ".join(problems))
    if topology.mininet_available:
        print("Mininet detected, but Phase 1 currently runs the reproducible fallback simulator.")
    else:
        print("Mininet unavailable: running fallback logical network simulator.")
    data = run_phase1_experiments(topology, args.results_dir)
    make_plots(data, args.plots_dir)
    for name, rows in data.items(): print(f"{name}: {summarize(rows)}")
    print(f"CSV results: {args.results_dir}")
    print(f"Plots: {args.plots_dir}")


if __name__ == "__main__": main()
