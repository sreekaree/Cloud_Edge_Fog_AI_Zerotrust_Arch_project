"""Configuration-backed IoMT identity registry."""
from dataclasses import dataclass, replace
from pathlib import Path
import yaml
from .trust_state import TrustState


@dataclass(frozen=True)
class DeviceIdentity:
    device_id: str
    tenant_id: str
    device_type: str
    ip_address: str
    identity_status: str
    authorization_status: str
    trust_state: TrustState
    allowed_services: tuple[str, ...]


class IdentityRegistry:
    def __init__(self, identities: dict[str, DeviceIdentity]):
        self._identities = identities

    @classmethod
    def from_config(cls, path: str | Path):
        with Path(path).open(encoding="utf-8") as stream:
            config = yaml.safe_load(stream)
        identities = {}
        for device_id, data in config["identities"].items():
            identities[device_id] = DeviceIdentity(
                device_id=device_id, tenant_id=data["tenant_id"], device_type=data["device_type"],
                ip_address=data["ip_address"], identity_status=data["identity_status"],
                authorization_status=data["authorization_status"], trust_state=TrustState(data["trust_state"]),
                allowed_services=tuple(data["allowed_services"]),
            )
        return cls(identities)

    def get(self, device_id: str) -> DeviceIdentity | None:
        return self._identities.get(device_id)

    def set_trust_state(self, device_id: str, state: TrustState) -> None:
        self._identities[device_id] = replace(self._identities[device_id], trust_state=state)

    def revoke(self, device_id: str) -> None:
        self.set_trust_state(device_id, TrustState.REVOKED)

    def restore(self, device_id: str) -> None:
        self.set_trust_state(device_id, TrustState.TRUSTED)

    def all(self) -> tuple[DeviceIdentity, ...]:
        return tuple(self._identities.values())
