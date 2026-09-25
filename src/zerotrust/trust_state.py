"""Deterministic trust states used by the Phase 2 policy engine."""
from enum import Enum


class TrustState(str, Enum):
    TRUSTED = "TRUSTED"
    SUSPICIOUS = "SUSPICIOUS"
    REVOKED = "REVOKED"
