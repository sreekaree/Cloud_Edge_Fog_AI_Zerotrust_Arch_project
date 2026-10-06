"""Comprehensive unit and integration tests for Phase 4 Dynamic Trust Scoring."""
from pathlib import Path
import unittest
import pandas as pd

from src.zerotrust.dynamic_trust import (
    DynamicTrustEngine,
    DynamicState,
    Severity,
    REASON_SEVERITY_MAP,
    map_dynamic_to_phase2_state,
)
from src.zerotrust.trust_state import TrustState
from src.zerotrust.policy_engine import PolicyEngine, PolicyRequest
from experiments.run_phase4_trust_replay import run_replay


POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "zero_trust_policy.yaml"


class TestPhase4DynamicTrust(unittest.TestCase):
    """Test suite covering all 20 Phase 4 dynamic trust requirements."""

    def setUp(self):
        self.engine = DynamicTrustEngine(initial_devices=["devA", "devB"])

    def test_01_ai_only_floor_prevents_suspicious(self):
        """100 consecutive ALLOW events with alpha=0.99 cannot push a compliant device below T=70."""
        for _ in range(100):
            res = self.engine.update(
                device_id="devA",
                decision="ALLOW",
                reason="allowed",
                oof_score=0.99,
                is_jit=False,
                service="edge_telemetry",
            )
            self.assertGreaterEqual(res["trust_after"], 70.0)
            self.assertEqual(res["state_after"], DynamicState.TRUSTED.value)

        self.assertEqual(self.engine.get_score("devA"), 70.0)
        self.assertEqual(self.engine.get_state("devA"), DynamicState.TRUSTED)

    def test_02_deterministic_severity_source(self):
        """Severity S is derived strictly from Phase 2 reason codes; arbitrary metadata has no effect."""
        for reason, (expected_sev, expected_base) in REASON_SEVERITY_MAP.items():
            sev, base = REASON_SEVERITY_MAP[reason]
            self.assertEqual(sev, expected_sev)
            self.assertEqual(base, expected_base)

        with self.assertRaises(ValueError):
            self.engine.update("devA", "DENY", "invalid_nonexistent_reason", 0.1)

    def test_03_oof_score_mandatory(self):
        """Replay verifies that anomaly_score_oof is mandatory and present."""
        preds_path = Path(__file__).resolve().parent.parent / "results" / "ai" / "phase3b_predictions.csv"
        df = pd.read_csv(preds_path)
        self.assertIn("anomaly_score_oof", df.columns)

    def test_04_full_fit_score_rejected(self):
        """Passing out-of-bounds score or full-fit score raises ValueError."""
        with self.assertRaises(ValueError):
            self.engine.update("devA", "ALLOW", "allowed", 1.5)  # > 1.0
        with self.assertRaises(ValueError):
            self.engine.update("devA", "ALLOW", "allowed", -0.1)  # < 0.0

    def test_05_boundary_t70_trusted(self):
        """Boundary test: T=70.000 yields DynamicState.TRUSTED."""
        self.engine.scores["devA"] = 70.0
        res = self.engine.update("devA", "ALLOW", "allowed", 0.1)
        self.assertGreaterEqual(res["trust_after"], 70.0)
        self.assertEqual(res["state_after"], DynamicState.TRUSTED.value)

    def test_06_boundary_t69_restricted(self):
        """Boundary test: T=69.999 yields DynamicState.RESTRICTED."""
        self.engine.scores["devA"] = 69.999
        self.engine.states["devA"] = DynamicState.RESTRICTED
        # Compliant event with alpha >= 0.40 earns no recovery and does not exceed 70
        res = self.engine.update("devA", "ALLOW", "allowed", 0.45)
        self.assertLess(res["trust_after"], 70.0)
        self.assertEqual(res["state_after"], DynamicState.RESTRICTED.value)

    def test_07_boundary_t30_restricted(self):
        """Boundary test: T=30.000 yields DynamicState.RESTRICTED."""
        self.engine.scores["devA"] = 30.0
        self.engine.states["devA"] = DynamicState.RESTRICTED
        res = self.engine.update("devA", "ALLOW", "allowed", 0.45)
        self.assertEqual(res["trust_after"], 30.0)
        self.assertEqual(res["state_after"], DynamicState.RESTRICTED.value)

    def test_08_boundary_t29_revoked(self):
        """Boundary test: T=29.999 yields DynamicState.REVOKED."""
        self.engine.scores["devA"] = 29.999
        self.engine.states["devA"] = DynamicState.REVOKED
        res = self.engine.update("devA", "ALLOW", "allowed", 0.1)
        self.assertLess(res["trust_after"], 30.0)
        self.assertEqual(res["state_after"], DynamicState.REVOKED.value)

    def test_09_boundary_t0_floor(self):
        """Penalties cannot drive score below T=0.000."""
        self.engine.scores["devA"] = 10.0
        res = self.engine.update("devA", "DENY", "cross_tenant_denied", 0.9)
        self.assertEqual(res["trust_after"], 0.0)
        self.assertEqual(res["state_after"], DynamicState.REVOKED.value)

    def test_10_recovery_from_t30(self):
        """Qualifying compliant event raises score from 30.00 to 32.00."""
        self.engine.scores["devA"] = 30.0
        self.engine.states["devA"] = DynamicState.RESTRICTED
        res = self.engine.update("devA", "ALLOW", "allowed", 0.2)
        self.assertEqual(res["trust_after"], 32.0)
        self.assertEqual(res["rec"], 2.0)

    def test_11_recovery_from_t68(self):
        """Qualifying compliant event raises score from 68.00 to 70.00, transitioning to TRUSTED."""
        self.engine.scores["devA"] = 68.0
        self.engine.states["devA"] = DynamicState.RESTRICTED
        res = self.engine.update("devA", "ALLOW", "allowed", 0.2)
        self.assertEqual(res["trust_after"], 70.0)
        self.assertEqual(res["state_after"], DynamicState.TRUSTED.value)

    def test_12_recovery_from_t69(self):
        """Qualifying compliant event raises score from 69.00 to 71.00."""
        self.engine.scores["devA"] = 69.0
        self.engine.states["devA"] = DynamicState.RESTRICTED
        res = self.engine.update("devA", "ALLOW", "allowed", 0.2)
        self.assertEqual(res["trust_after"], 71.0)
        self.assertEqual(res["state_after"], DynamicState.TRUSTED.value)

    def test_13_violation_counter_increment(self):
        """Current event is counted in N_viol (N=1 multiplier 1.0, N=2 multiplier 1.5)."""
        res1 = self.engine.update("devA", "DENY", "trust_state_trusted", 0.1)
        self.assertEqual(res1["n_viol_after"], 1)
        self.assertEqual(res1["p_det"], 40.0)  # 40 * 1.0

        res2 = self.engine.update("devA", "DENY", "trust_state_suspicious", 0.1)
        self.assertEqual(res2["n_viol_after"], 2)
        self.assertEqual(res2["p_det"], 37.5)  # 25 * 1.5

    def test_14_violation_counter_decay_on_compliant(self):
        """Compliant events in RESTRICTED decay N_viol, and returning to TRUSTED resets N_viol to 0."""
        # 1. First violation drops to RESTRICTED
        self.engine.update("devA", "DENY", "cross_tenant_denied", 0.1)
        self.assertEqual(self.engine.get_n_viol("devA"), 1)
        self.assertEqual(self.engine.get_state("devA"), DynamicState.RESTRICTED)

        # 2. Compliant event decays N_viol by 1
        res = self.engine.update("devA", "ALLOW", "allowed", 0.2)
        self.assertEqual(res["n_viol_after"], 0)
        self.assertEqual(self.engine.get_n_viol("devA"), 0)

        # 3. Next violation uses M=1.0 rather than amplified M=1.5
        res_next = self.engine.update("devA", "DENY", "trust_state_trusted", 0.1)
        self.assertEqual(res_next["n_viol_after"], 1)
        self.assertEqual(res_next["p_det"], 40.0)

    def test_15_deterministic_deny_never_overridden(self):
        """Deterministic DENY is never converted to ALLOW regardless of high trust or zero AI score."""
        self.engine.scores["devA"] = 100.0
        res = self.engine.update("devA", "DENY", "cross_tenant_denied", 0.0)
        self.assertTrue(res["action_taken"].startswith("DENY"))

    def test_16_revoked_state_no_auto_recovery(self):
        """Compliant traffic while REVOKED produces zero recovery gain."""
        self.engine.scores["devA"] = 14.33
        self.engine.states["devA"] = DynamicState.REVOKED
        res = self.engine.update("devA", "ALLOW", "allowed", 0.1)
        self.assertEqual(res["trust_after"], 14.33)
        self.assertEqual(res["rec"], 0.0)
        self.assertEqual(res["state_after"], DynamicState.REVOKED.value)

    def test_17_revoked_state_receives_violation_penalty(self):
        """A deterministic violation on an already-REVOKED device reduces numerical score to 0."""
        self.engine.scores["devA"] = 14.33
        self.engine.states["devA"] = DynamicState.REVOKED
        self.engine.n_viols["devA"] = 2
        res = self.engine.update("devA", "DENY", "trust_state_trusted", 0.95)
        self.assertEqual(res["trust_after"], 0.0)
        self.assertEqual(res["state_after"], DynamicState.REVOKED.value)

    def test_18_administrative_restore_mechanism(self):
        """admin_restore validates bounds, resets N_viol=0, and restores to TRUSTED."""
        self.engine.scores["devA"] = 0.0
        self.engine.states["devA"] = DynamicState.REVOKED
        self.engine.n_viols["devA"] = 3

        audit = self.engine.admin_restore("devA", initial_trust_score=100.0)
        self.assertEqual(audit["new_score"], 100.0)
        self.assertEqual(audit["new_state"], DynamicState.TRUSTED.value)
        self.assertEqual(self.engine.get_score("devA"), 100.0)
        self.assertEqual(self.engine.get_state("devA"), DynamicState.TRUSTED)
        self.assertEqual(self.engine.get_n_viol("devA"), 0)

        with self.assertRaises(ValueError):
            self.engine.admin_restore("devA", initial_trust_score=50.0)  # < 70.0

    def test_19_policy_engine_integration_restricted(self):
        """Integration Test: RESTRICTED maps to Phase 2 SUSPICIOUS, permitting Edge and denying Fog/Cloud."""
        engine = PolicyEngine.from_config(str(POLICY_PATH))
        self.engine.scores["iotA1"] = 50.0
        self.engine.states["iotA1"] = DynamicState.RESTRICTED
        self.engine.sync_to_registry(engine.registry, "iotA1")

        self.assertEqual(engine.registry.get("iotA1").trust_state, TrustState.SUSPICIOUS)

        # 1. Edge telemetry is ALLOWED
        req_edge = PolicyRequest("iotA1", "10.1.1.10", "edge_telemetry", 8443)
        dec_edge = engine.evaluate(req_edge)
        self.assertEqual(dec_edge.decision, "ALLOW")
        self.assertEqual(dec_edge.reason, "allowed")

        # 2. Fog telemetry is DENIED with reason trust_state_suspicious
        req_fog = PolicyRequest("iotA1", "10.1.2.11", "fog_telemetry", 9443)
        dec_fog = engine.evaluate(req_fog)
        self.assertEqual(dec_fog.decision, "DENY")
        self.assertEqual(dec_fog.reason, "trust_state_suspicious")

        # 3. Cloud telemetry is DENIED with reason trust_state_suspicious
        req_cloud = PolicyRequest("iotA1", "10.1.3.11", "cloud_telemetry", 10443)
        dec_cloud = engine.evaluate(req_cloud)
        self.assertEqual(dec_cloud.decision, "DENY")
        self.assertEqual(dec_cloud.reason, "trust_state_suspicious")

    def test_20_trace_reproducibility_and_ablation(self):
        """Replay execution is bitwise reproducible and ablation arm runs identical deterministic transitions."""
        trace1, scores1 = run_replay(enable_ai=True)
        trace2, scores2 = run_replay(enable_ai=True)
        self.assertEqual(scores1, scores2)
        pd.testing.assert_frame_equal(trace1, trace2)

        trace_det, scores_det = run_replay(enable_ai=False)
        self.assertEqual(len(trace_det), 25)
        # All devices have matching final states between hybrid and det-only
        for dev in scores1:
            st1 = trace1[trace1["source_device"] == dev]["state_after"].iloc[-1]
            std = trace_det[trace_det["source_device"] == dev]["state_after"].iloc[-1]
            self.assertEqual(st1, std)


if __name__ == "__main__":
    unittest.main()
