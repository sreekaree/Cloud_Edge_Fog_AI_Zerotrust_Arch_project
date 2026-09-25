import unittest
from pathlib import Path
from src.zerotrust.policy_engine import PolicyEngine, PolicyRequest
from src.zerotrust.trust_state import TrustState

POLICY = Path(__file__).resolve().parents[1] / "config" / "zero_trust_policy.yaml"


class ZeroTrustPrivilegeTests(unittest.TestCase):
    def test_suspicious_state_restricts_fog_access(self):
        engine = PolicyEngine.from_config(POLICY); engine.registry.set_trust_state("iotA2", TrustState.SUSPICIOUS)
        result = engine.evaluate(PolicyRequest("iotA2", "10.1.2.11", "fog_telemetry", 9443))
        self.assertEqual((result.decision, result.reason), ("DENY", "trust_state_suspicious"))
    def test_temporary_privilege_is_removed_deterministically(self):
        engine = PolicyEngine.from_config(POLICY); request = PolicyRequest("iotA2", "10.1.2.11", "fog_diagnostic", 9555)
        self.assertEqual(engine.evaluate(request).decision, "DENY")
        engine.privileges.grant("iotA2", "fog_diagnostic"); self.assertEqual(engine.evaluate(request).decision, "ALLOW")
        engine.privileges.revoke("iotA2", "fog_diagnostic"); self.assertEqual(engine.evaluate(request).decision, "DENY")
