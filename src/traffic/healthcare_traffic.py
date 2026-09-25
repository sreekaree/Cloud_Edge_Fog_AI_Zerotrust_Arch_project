"""Deterministic, synthetic healthcare traffic generation."""
from dataclasses import dataclass
from src.devices.iomt_devices import IoMTDevice


@dataclass(frozen=True)
class SyntheticPacket:
    packet_id: str
    timestamp_seconds: float
    device: IoMTDevice
    size_bytes: int


def generate_packets(devices: list[IoMTDevice], duration_seconds: float, packet_size_bytes: int):
    for device in devices:
        for index, timestamp in enumerate(device.packet_times(duration_seconds), start=1):
            yield SyntheticPacket(f"{device.device_id}-{index}", timestamp, device, packet_size_bytes)
