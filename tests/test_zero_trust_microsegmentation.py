import unittest
from pathlib import Path
from src.zerotrust.policy_engine import PolicyEngine, PolicyRequest

POLICY = Path(__file__).resolve().parents[1] / "config" / "zero_trust_policy.yaml"


class ZeroTrustSegmentationTests(unittest.TestCase):
    def test_cross_tenant_edge_is_denied(self):
        engine = PolicyEngine.from_config(POLICY)
        result = engine.evaluate(PolicyRequest("iotA1", "10.2.1.10", "edge_telemetry", 8443))
        self.assertEqual((result.decision, result.reason), ("DENY", "cross_tenant_denied"))
