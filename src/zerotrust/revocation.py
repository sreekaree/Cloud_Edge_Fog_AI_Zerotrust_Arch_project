"""Small explicit revocation facade for Phase 2 experiments."""
from .identity import IdentityRegistry


def revoke_device(registry: IdentityRegistry, device_id: str) -> None: registry.revoke(device_id)
def restore_device(registry: IdentityRegistry, device_id: str) -> None: registry.restore(device_id)
