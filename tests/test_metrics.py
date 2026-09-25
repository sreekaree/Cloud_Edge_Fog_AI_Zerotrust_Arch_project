import unittest
from pathlib import Path
from src.experiments.latency_experiment import FallbackSimulator
from src.topology.healthcare_topology import load_topology
from src.utils.metrics import summarize

ROOT = Path(__file__).resolve().parents[1]


class MetricTests(unittest.TestCase):
    def test_measured_latency_increases_with_path_length(self):
        simulator = FallbackSimulator(load_topology(ROOT / "config" / "network_config.yaml"))
        edge, fog, cloud = simulator.measure("edge"), simulator.measure("fog"), simulator.measure("cloud")
        self.assertLess(summarize(edge)["mean_latency_ms"], summarize(fog)["mean_latency_ms"])
        self.assertLess(summarize(fog)["mean_latency_ms"], summarize(cloud)["mean_latency_ms"])
        self.assertGreater(summarize(cloud)["mean_throughput_mbps"], 0)
