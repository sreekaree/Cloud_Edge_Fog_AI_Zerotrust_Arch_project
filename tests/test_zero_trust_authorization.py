import unittest
from src.zerotrust.authorization import IPTABLES_EXECUTABLE, MininetAuthorizer


class FakeHost:
    name = "iotA1"
    def __init__(self): self.commands = []
    def cmd(self, command):
        self.commands.append(command)
        if "ping" in command:
            return "1 packets transmitted, 0 received, +1 errors, 100% packet loss"
        return ""


class ZeroTrustAuthorizationTests(unittest.TestCase):
    def test_denial_uses_absolute_iptables_path_and_removes_rule(self):
        host = FakeHost(); authorizer = MininetAuthorizer()
        result, enforcement = authorizer.execute(host, "10.2.1.10", allowed=False)
        self.assertEqual((result["received"], enforcement), (0, "iptables_output_icmp_drop"))
        self.assertEqual(host.commands[0], f"{IPTABLES_EXECUTABLE} -I OUTPUT -d 10.2.1.10 -p icmp -j DROP")
        self.assertEqual(host.commands[-1], f"{IPTABLES_EXECUTABLE} -D OUTPUT -d 10.2.1.10 -p icmp -j DROP")
