import unittest
from src.devices.iomt_devices import IoMTDevice


class DeviceTests(unittest.TestCase):
    def test_packet_times_follow_interval(self):
        d = IoMTDevice("x", "ECG", "hospital_a", "10.1.1.1", 2, "high")
        self.assertEqual(list(d.packet_times(5)), [0.0, 2.0, 4.0])
