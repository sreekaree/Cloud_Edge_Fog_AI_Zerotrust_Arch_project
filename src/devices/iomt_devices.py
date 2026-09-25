"""Synthetic IoMT device definitions; no patient data is represented."""
from dataclasses import dataclass


@dataclass(frozen=True)
class IoMTDevice:
    device_id: str
    device_type: str
    tenant: str
    ip_address: str
    interval_seconds: float
    priority: str

    def packet_times(self, duration_seconds: float):
        """Return deterministic synthetic-data transmission times."""
        time = 0.0
        while time < duration_seconds:
            yield time
            time += self.interval_seconds
