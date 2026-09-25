import unittest
from pathlib import Path
from src.zerotrust.policy_engine import PolicyEngine, PolicyRequest

POLICY = Path(__file__).resolve().parents[1] / "config" / "zero_trust_policy.yaml"


class ZeroTrustPolicyTests(unittest.TestCase):
    def setUp(self): self.engine = PolicyEngine.from_config(POLICY)
    def test_authorized_same_tenant_service_is_allowed(self):
        decision = self.engine.evaluate(PolicyRequest("iotA1", "10.1.1.10", "edge_telemetry", 8443))
        self.assertEqual(decision.decision, "ALLOW")
    def test_unauthorized_port_is_denied(self):
        decision = self.engine.evaluate(PolicyRequest("iotA1", "10.1.1.10", "edge_telemetry", 22))
        self.assertEqual((decision.decision, decision.reason), ("DENY", "service_or_port_denied"))
