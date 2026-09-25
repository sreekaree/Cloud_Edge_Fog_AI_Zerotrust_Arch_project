import unittest
import ipaddress
from src.topology.mininet_topology import (
    DEVICE_SPECS,
    EXPECTED_HOST_NAMES,
    MAX_INTERFACE_PORTS,
    MEASUREMENT_DESTINATIONS,
    NODE_INTERFACE_ADDRESSES,
    SWITCH_ALIASES,
    SWITCH_DPIDS,
    mininet_is_available,
    require_mininet,
)


class MininetBackendTests(unittest.TestCase):
    def test_addressing_and_measurement_destinations(self):
        device_ips = {name: ipaddress.ip_interface(address).ip for name, address in DEVICE_SPECS}
        self.assertEqual(device_ips["iotA1"], ipaddress.ip_address("10.1.1.11"))
        self.assertEqual(device_ips["iotB1"], ipaddress.ip_address("10.2.1.11"))
        assigned_ips = set(device_ips.values())
        for interfaces in NODE_INTERFACE_ADDRESSES.values():
            assigned_ips.update(ipaddress.ip_interface(address).ip for _, address in interfaces)
        self.assertEqual(len(assigned_ips), 18)
        for destinations in MEASUREMENT_DESTINATIONS.values():
            for address in destinations.values():
                self.assertIn(ipaddress.ip_address(address), assigned_ips)

    def test_topology_inventory_and_dpids(self):
        self.assertEqual(len(EXPECTED_HOST_NAMES), 11)
        self.assertEqual(len(SWITCH_DPIDS), 8)
        self.assertEqual(len(set(SWITCH_DPIDS.values())), 8)
        self.assertEqual(set(SWITCH_ALIASES), set(SWITCH_DPIDS))
        self.assertEqual(len(set(SWITCH_ALIASES.values())), 8)
        for dpid in SWITCH_DPIDS.values():
            self.assertRegex(dpid, r"^[0-9a-f]{16}$")

    def test_generated_interface_names_fit_linux_limit(self):
        for node_name, max_port in MAX_INTERFACE_PORTS.items():
            interface_name = f"{node_name}-eth{max_port}"
            self.assertLessEqual(len(interface_name), 15, interface_name)

    def test_backend_imports_without_mininet(self):
        """Backend must be safely diagnosable on development hosts without Mininet."""
        if mininet_is_available():
            self.assertTrue(mininet_is_available())
        else:
            with self.assertRaises(RuntimeError):
                require_mininet()
