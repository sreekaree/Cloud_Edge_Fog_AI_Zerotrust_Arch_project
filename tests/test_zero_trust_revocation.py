import unittest
from pathlib import Path
from src.zerotrust.policy_engine import PolicyEngine, PolicyRequest
from src.zerotrust.revocation import revoke_device

POLICY = Path(__file__).resolve().parents[1] / "config" / "zero_trust_policy.yaml"


class ZeroTrustRevocationTests(unittest.TestCase):
    def test_revoked_device_is_denied(self):
        engine = PolicyEngine.from_config(POLICY); revoke_device(engine.registry, "iotA1")
        result = engine.evaluate(PolicyRequest("iotA1", "10.1.1.10", "edge_telemetry", 8443))
        self.assertEqual((result.decision, result.reason), ("DENY", "trust_state_revoked"))
