"""AI-Driven Dynamic Trust Scoring Engine for MedTrustEdge.

Combines deterministic Zero Trust policy outcomes with auxiliary machine learning
anomaly risk signals to compute continuous device trustworthiness scores.
"""
from dataclasses import dataclass
from enum import Enum
import time
from typing import Any

from .identity import IdentityRegistry
from .policy_engine import PolicyEngine, PolicyRequest, Decision
from .trust_state import TrustState


class DynamicState(str, Enum):
    TRUSTED = "TRUSTED"
    RESTRICTED = "RESTRICTED"
    REVOKED = "REVOKED"


class Severity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Deterministic reason code mapping verified against Phase 2 policy_engine.py
REASON_SEVERITY_MAP: dict[str, tuple[Severity, float]] = {
    "allowed": (Severity.NONE, 0.0),
    "trust_state_suspicious": (Severity.MEDIUM, 25.0),
    "trust_state_trusted": (Severity.HIGH, 40.0),
    "service_or_port_denied": (Severity.HIGH, 40.0),
    "least_privilege_denied": (Severity.HIGH, 40.0),
    "unknown_destination": (Severity.HIGH, 40.0),
    "device_not_authorized": (Severity.HIGH, 40.0),
    "identity_inactive": (Severity.HIGH, 40.0),
    "unknown_device": (Severity.HIGH, 40.0),
    "policy_inactive": (Severity.HIGH, 40.0),
    "cross_tenant_denied": (Severity.CRITICAL, 50.0),
    "trust_state_revoked": (Severity.CRITICAL, 100.0),
}


def map_dynamic_to_phase2_state(dynamic_state: DynamicState) -> TrustState:
    """Maps continuous Phase 4 dynamic trust states into discrete Phase 2 TrustStates."""
    if dynamic_state == DynamicState.TRUSTED:
        return TrustState.TRUSTED
    elif dynamic_state == DynamicState.RESTRICTED:
        return TrustState.SUSPICIOUS
    elif dynamic_state == DynamicState.REVOKED:
        return TrustState.REVOKED
    raise ValueError(f"Unknown dynamic trust state: {dynamic_state}")


class DynamicTrustEngine:
    """Chronological dynamic trust scoring engine with Zero Trust dominance and AI floor."""

    def __init__(self, initial_devices: list[str] | None = None, enable_ai: bool = True):
        self.enable_ai = enable_ai
        self.scores: dict[str, float] = {}
        self.states: dict[str, DynamicState] = {}
        self.n_viols: dict[str, int] = {}

        devices = initial_devices or ["iotA1", "iotA2", "iotA3", "iotB1", "iotB2", "iotB3"]
        for dev in devices:
            self.scores[dev] = 100.0
            self.states[dev] = DynamicState.TRUSTED
            self.n_viols[dev] = 0

    def get_score(self, device_id: str) -> float:
        return self.scores.get(device_id, 100.0)

    def get_state(self, device_id: str) -> DynamicState:
        return self.states.get(device_id, DynamicState.TRUSTED)

    def get_n_viol(self, device_id: str) -> int:
        return self.n_viols.get(device_id, 0)

    def calculate_ai_penalty(self, oof_score: float, is_jit: bool) -> float:
        """Calculates auxiliary AI penalty capped at 15.0."""
        if not self.enable_ai or is_jit or oof_score <= 0.40:
            return 0.0
        return min(15.0, (100.0 / 3.0) * (oof_score - 0.40))

    def update(
        self,
        device_id: str,
        decision: str,
        reason: str,
        oof_score: float,
        is_jit: bool = False,
        service: str | None = None,
    ) -> dict[str, Any]:
        """Evaluates an incoming event, updates continuous trust, and applies state guardrails."""
        if device_id not in self.scores:
            self.scores[device_id] = 100.0
            self.states[device_id] = DynamicState.TRUSTED
            self.n_viols[device_id] = 0

        if not (0.0 <= oof_score <= 1.0):
            raise ValueError(f"OOF anomaly score must be within [0.0, 1.0], got {oof_score}")

        if reason not in REASON_SEVERITY_MAP:
            raise ValueError(f"Unrecognized reason code: '{reason}'. Must be in REASON_SEVERITY_MAP.")

        severity, p_base = REASON_SEVERITY_MAP[reason]
        is_viol = (severity != Severity.NONE) or (decision == "DENY")

        trust_before = self.scores[device_id]
        state_before = self.states[device_id]
        n_viol_before = self.n_viols[device_id]

        # 1. Deterministic penalty
        if is_viol:
            n_viol_after = n_viol_before + 1
            if reason == "trust_state_revoked":
                p_det = 100.0
            else:
                multiplier = 1.0 + 0.50 * (n_viol_after - 1)
                p_det = min(100.0, p_base * multiplier)
        else:
            n_viol_after = n_viol_before
            p_det = 0.0

        # 2. AI modulation penalty
        p_ai = self.calculate_ai_penalty(oof_score, is_jit)
        p_total = p_det + p_ai

        # 3. Recovery gain
        qualifies_rec = (not is_viol) and (decision == "ALLOW") and (state_before != DynamicState.REVOKED)
        if self.enable_ai:
            qualifies_rec = qualifies_rec and (oof_score < 0.40)
        rec = 2.0 if qualifies_rec else 0.0

        # 4. Score update and floor guardrails
        if is_viol:
            trust_after = max(0.0, trust_before - p_total)
        else:
            cand = trust_before - p_total + rec
            if trust_before >= 70.0:
                # AI-Only Trust Floor: Compliant devices cannot drop below 70.0
                trust_after = max(70.0, min(100.0, cand))
            elif state_before == DynamicState.REVOKED:
                # REVOKED devices cannot auto-recover
                trust_after = trust_before
            else:
                # RESTRICTED state: AI-only cannot revoke; recovery allowed up toward 70
                trust_after = max(30.0, min(100.0, cand))

        # 5. State assignment
        if trust_after >= 70.0:
            state_after = DynamicState.TRUSTED
        elif trust_after >= 30.0:
            state_after = DynamicState.RESTRICTED
        else:
            state_after = DynamicState.REVOKED

        # 6. Violation counter decay / reset
        if state_after == DynamicState.TRUSTED:
            # Full reset upon returning to TRUSTED
            n_viol_after = 0
        elif (not is_viol) and (state_before == DynamicState.RESTRICTED):
            # Step decay by 1 on intermediate compliant events while in RESTRICTED
            n_viol_after = max(0, n_viol_before - 1)

        # Commit state
        self.scores[device_id] = trust_after
        self.states[device_id] = state_after
        self.n_viols[device_id] = n_viol_after

        # 7. Action taken
        if decision == "DENY":
            action = f"DENY ({reason})"
        elif state_before == DynamicState.REVOKED:
            action = "DENY (quarantined/revoked)"
        elif state_before == DynamicState.RESTRICTED:
            if service == "edge_telemetry":
                action = "ALLOW (RESTRICTED: Edge telemetry)"
            else:
                action = "RESTRICTED: DENY (Tier disallowed)"
        else:
            action = "ALLOW"

        return {
            "device_id": device_id,
            "decision": decision,
            "reason": reason,
            "severity": severity.value,
            "oof_score": oof_score,
            "is_jit": is_jit,
            "p_det": p_det,
            "p_ai": p_ai,
            "p_total": p_total,
            "rec": rec,
            "trust_before": trust_before,
            "trust_after": trust_after,
            "state_before": state_before.value,
            "state_after": state_after.value,
            "mapped_phase2_state": map_dynamic_to_phase2_state(state_after).value,
            "n_viol_before": n_viol_before,
            "n_viol_after": n_viol_after,
            "action_taken": action,
        }

    def admin_restore(
        self,
        device_id: str,
        initial_trust_score: float = 100.0,
        operator_id: str = "security_admin",
        reason: str = "Forensic inspection cleared",
    ) -> dict[str, Any]:
        """Administratively restores a REVOKED device with audit logging."""
        if device_id not in self.scores:
            raise ValueError(f"Unknown device: {device_id}")

        if not (70.0 <= initial_trust_score <= 100.0):
            raise ValueError(
                f"initial_trust_score must be within [70.0, 100.0], got {initial_trust_score}"
            )

        prev_score = self.scores[device_id]
        prev_state = self.states[device_id]

        self.scores[device_id] = float(initial_trust_score)
        self.states[device_id] = DynamicState.TRUSTED
        self.n_viols[device_id] = 0

        return {
            "device_id": device_id,
            "operator_id": operator_id,
            "reason": reason,
            "prev_score": prev_score,
            "prev_state": prev_state.value,
            "new_score": float(initial_trust_score),
            "new_state": DynamicState.TRUSTED.value,
            "n_viol": 0,
            "timestamp": time.time(),
        }

    def sync_to_registry(self, registry: IdentityRegistry, device_id: str) -> None:
        """Propagates Phase 4 dynamic trust state to an IdentityRegistry instance."""
        target_state = map_dynamic_to_phase2_state(self.get_state(device_id))
        registry.set_trust_state(device_id, target_state)
