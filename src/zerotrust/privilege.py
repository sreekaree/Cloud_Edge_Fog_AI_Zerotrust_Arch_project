"""Deterministic, explicitly removed just-in-time privileges."""
class TemporaryPrivilegeManager:
    def __init__(self): self._grants: dict[str, set[str]] = {}
    def grant(self, device_id: str, service: str) -> None: self._grants.setdefault(device_id, set()).add(service)
    def revoke(self, device_id: str, service: str) -> None: self._grants.get(device_id, set()).discard(service)
    def allows(self, device_id: str, service: str) -> bool: return service in self._grants.get(device_id, set())
