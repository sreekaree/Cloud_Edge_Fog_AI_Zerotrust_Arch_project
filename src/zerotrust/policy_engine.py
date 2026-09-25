"""Deterministic least-privilege policy evaluation; no AI inference."""
from dataclasses import dataclass
from pathlib import Path
import time
import yaml
from .identity import IdentityRegistry
from .privilege import TemporaryPrivilegeManager
from .trust_state import TrustState


@dataclass(frozen=True)
class PolicyRequest:
    device_id: str
    destination_ip: str
    service: str
    port: int


@dataclass(frozen=True)
class Decision:
    decision: str
    reason: str
    policy_id: str
    decision_latency_ms: float


class PolicyEngine:
    def __init__(self, registry: IdentityRegistry, config: dict, privileges: TemporaryPrivilegeManager | None = None):
        self.registry, self.config = registry, config
        self.privileges = privileges or TemporaryPrivilegeManager()

    @classmethod
    def from_config(cls, path: str | Path):
        registry = IdentityRegistry.from_config(path)
        with Path(path).open(encoding="utf-8") as stream: config = yaml.safe_load(stream)
        return cls(registry, config)

    def evaluate(self, request: PolicyRequest) -> Decision:
        start = time.perf_counter()
        policy = self.config["policy"]
        identity = self.registry.get(request.device_id)
        reason = "allowed"
        if identity is None: reason = "unknown_device"
        elif not policy["active"]: reason = "policy_inactive"
        elif identity.identity_status != "active": reason = "identity_inactive"
        elif identity.authorization_status != "authorized": reason = "device_not_authorized"
        else:
            same_destination = [item for item in self.config["resources"].values() if item["destination_ip"] == request.destination_ip]
            resource = next((item for item in same_destination if item["service"] == request.service and int(item["port"]) == int(request.port)), None)
            if not same_destination: reason = "unknown_destination"
            elif resource is None: reason = "service_or_port_denied"
            elif resource["tenant_id"] != identity.tenant_id: reason = "cross_tenant_denied"
            elif resource["service"] != request.service or int(resource["port"]) != int(request.port): reason = "service_or_port_denied"
            elif identity.trust_state is TrustState.REVOKED: reason = "trust_state_revoked"
            elif request.service not in policy["trust_state_allowed_services"][identity.trust_state.value] and not self.privileges.allows(identity.device_id, request.service): reason = f"trust_state_{identity.trust_state.value.lower()}"
            elif request.service not in identity.allowed_services and not self.privileges.allows(identity.device_id, request.service): reason = "least_privilege_denied"
        allowed = reason == "allowed"
        return Decision("ALLOW" if allowed else "DENY", reason, policy["policy_id"], (time.perf_counter() - start) * 1000)
