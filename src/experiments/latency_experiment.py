"""Fallback discrete-event network experiment runner.

This estimates transport timing from configured link propagation, serialization and
processing delays. It is a logical simulator, not a substitute for Mininet emulation.
"""
import random
from pathlib import Path
from src.topology.healthcare_topology import HealthcareTopology
from src.traffic.healthcare_traffic import generate_packets
from src.utils.metrics import write_csv


class FallbackSimulator:
    def __init__(self, topology: HealthcareTopology):
        self.topology = topology
        self.config = topology.config
        self.random = random.Random(self.config["simulation"]["random_seed"])

    def measure(self, destination: str) -> list[dict]:
        duration = float(self.config["simulation"]["duration_seconds"])
        size = int(self.config["simulation"]["default_packet_size_bytes"])
        rows = []
        for packet in generate_packets(self.topology.devices, duration, size):
            latency, loss, bottleneck = self._traverse(packet.size_bytes, self.topology.route_for(packet.device, destination))
            rows.append({
                "timestamp_seconds": round(packet.timestamp_seconds, 6), "packet_id": packet.packet_id,
                "source": packet.device.device_id, "source_ip": packet.device.ip_address,
                "tenant": packet.device.tenant, "device_type": packet.device.device_type,
                "priority": packet.device.priority, "destination": destination, "packet_count": 1,
                "packet_size_bytes": packet.size_bytes, "latency_ms": round(latency, 6),
                "throughput_mbps": round((packet.size_bytes * 8 / 1_000_000) / (latency / 1000), 6) if not loss else 0.0,
                "packet_loss": int(loss),
            })
        return rows

    def _traverse(self, size_bytes: int, links: list[str]) -> tuple[float, bool, float]:
        latency, bottleneck = 0.0, float("inf")
        for link_name in links:
            link = self.config["links"][link_name]
            bandwidth = float(link["bandwidth_mbps"])
            latency += float(link["latency_ms"]) + (size_bytes * 8 / bandwidth / 1000)
            bottleneck = min(bottleneck, bandwidth)
            if self.random.random() < float(link["loss_percent"]) / 100:
                return latency, True, bottleneck
        if links == ["iomt_to_edge"]:
            latency += float(self.config["processing_delay_ms"]["edge"])
        elif links == ["iomt_to_edge", "edge_to_fog"]:
            latency += sum(float(self.config["processing_delay_ms"][key]) for key in ("edge", "fog"))
        else:
            latency += float(self.config["processing_delay_ms"]["cloud"])
        return latency, False, bottleneck


def run_phase1_experiments(topology: HealthcareTopology, results_dir: str | Path) -> dict[str, list[dict]]:
    """Run all required fallback experiments and persist their actual output."""
    simulator = FallbackSimulator(topology)
    results_dir = Path(results_dir)
    specs = {"edge_latency": "edge", "fog_latency": "fog", "end_to_end_latency": "cloud", "cloud_latency": "baseline_cloud"}
    experiments = {name: simulator.measure(destination) for name, destination in specs.items()}
    for name, rows in experiments.items(): write_csv(results_dir / f"{name}.csv", rows)
    comparison = []
    for distributed, baseline in zip(experiments["end_to_end_latency"], experiments["cloud_latency"]):
        comparison.extend((dict(distributed, destination="edge_fog_cloud"), dict(baseline, destination="cloud_only")))
    write_csv(results_dir / "baseline_comparison.csv", comparison)
    experiments["baseline_comparison"] = comparison
    return experiments
