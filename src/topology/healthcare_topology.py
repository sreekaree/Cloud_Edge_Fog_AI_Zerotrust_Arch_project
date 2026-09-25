"""Configurable logical Cloud--Fog--Edge topology."""
from dataclasses import dataclass
from pathlib import Path
import importlib.util
import ipaddress
import yaml

from src.devices.iomt_devices import IoMTDevice


@dataclass(frozen=True)
class Node:
    node_id: str
    role: str
    tenant: str | None
    ip_address: str


class HealthcareTopology:
    def __init__(self, config: dict):
        self.config = config
        self.cloud = Node(config["cloud"]["id"], "cloud", None, config["cloud"]["ip"])
        self.nodes = [self.cloud]
        self.devices = []
        self.tenant_nodes = {}
        for tenant, spec in config["tenants"].items():
            edge = Node(spec["edge"]["id"], "edge", tenant, spec["edge"]["ip"])
            fog = Node(spec["fog"]["id"], "fog", tenant, spec["fog"]["ip"])
            self.nodes.extend((edge, fog))
            self.tenant_nodes[tenant] = {"edge": edge, "fog": fog}
            self.devices.extend(IoMTDevice(
                device_id=item["id"], device_type=item["type"], tenant=tenant,
                ip_address=item["ip"], interval_seconds=float(item["interval_seconds"]),
                priority=item["priority"]
            ) for item in spec["devices"])

    @property
    def mininet_available(self) -> bool:
        return importlib.util.find_spec("mininet") is not None

    def validate(self) -> list[str]:
        """Validate node uniqueness and configured per-tenant subnet separation."""
        problems = []
        ids = [node.node_id for node in self.nodes] + [device.device_id for device in self.devices]
        if len(ids) != len(set(ids)):
            problems.append("Node/device identifiers must be unique.")
        addresses = [node.ip_address for node in self.nodes] + [device.ip_address for device in self.devices]
        if len(addresses) != len(set(addresses)):
            problems.append("IP addresses must be unique.")
        for tenant, items in self.tenant_nodes.items():
            prefix = "10.1." if tenant == "hospital_a" else "10.2."
            if any(not device.ip_address.startswith(prefix) for device in self.devices if device.tenant == tenant):
                problems.append(f"{tenant} IoMT devices are outside their tenant subnet.")
            if any(not node.ip_address.startswith(prefix) for node in items.values()):
                problems.append(f"{tenant} Edge/Fog nodes are outside their tenant subnet.")
        if ipaddress.ip_address(self.cloud.ip_address) not in ipaddress.ip_network("10.10.0.0/24"):
            problems.append("Cloud is outside 10.10.0.0/24.")
        return problems

    def route_for(self, device: IoMTDevice, destination: str) -> list[str]:
        """Return link classes traversed to the requested logical destination."""
        if destination == "edge": return ["iomt_to_edge"]
        if destination == "fog": return ["iomt_to_edge", "edge_to_fog"]
        if destination == "cloud": return ["iomt_to_edge", "edge_to_fog", "fog_to_cloud"]
        if destination == "baseline_cloud": return ["iomt_to_cloud_baseline"]
        raise ValueError(f"Unknown destination: {destination}")


def load_topology(config_path: str | Path) -> HealthcareTopology:
    with Path(config_path).open(encoding="utf-8") as stream:
        return HealthcareTopology(yaml.safe_load(stream))
