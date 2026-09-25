import unittest
from pathlib import Path
from src.topology.healthcare_topology import load_topology

ROOT = Path(__file__).resolve().parents[1]


class ConfigTests(unittest.TestCase):
    def setUp(self): self.topology = load_topology(ROOT / "config" / "network_config.yaml")
    def test_required_nodes_exist(self):
        self.assertEqual(len(self.topology.devices), 6)
        self.assertEqual(len(self.topology.tenant_nodes), 2)
        self.assertEqual(self.topology.cloud.node_id, "cloud")
    def test_addressing_and_routes_are_valid(self):
        self.assertFalse(self.topology.validate())
        self.assertEqual(self.topology.route_for(self.topology.devices[0], "cloud"), ["iomt_to_edge", "edge_to_fog", "fog_to_cloud"])
