import unittest
from pathlib import Path
from src.zerotrust.identity import IdentityRegistry
from src.zerotrust.trust_state import TrustState

POLICY = Path(__file__).resolve().parents[1] / "config" / "zero_trust_policy.yaml"


class ZeroTrustIdentityTests(unittest.TestCase):
    def test_six_deterministic_iomt_identities(self):
        registry = IdentityRegistry.from_config(POLICY)
        self.assertEqual(len(registry.all()), 6)
        self.assertEqual(registry.get("iotA1").ip_address, "10.1.1.11")
        self.assertEqual(registry.get("iotB1").tenant_id, "B")
        self.assertIs(registry.get("iotA1").trust_state, TrustState.TRUSTED)
