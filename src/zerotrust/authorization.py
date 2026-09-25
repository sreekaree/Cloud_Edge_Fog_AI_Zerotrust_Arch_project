"""Mininet request enforcement for Phase 2 experiments."""
import re

PING_SUMMARY = re.compile(r"(\d+) packets transmitted, (\d+) received,.*?(\d+)% packet loss", re.S)
PING_RTT = re.compile(r"= [^/]+/([^/]+)/")
IPTABLES_EXECUTABLE = "/usr/sbin/iptables"


class EnforcementError(RuntimeError): pass


def ping(host, destination_ip: str, count: int = 5) -> dict:
    raw = host.cmd(f"ping -c {count} -q {destination_ip}")
    match = PING_SUMMARY.search(raw)
    if not match: raise EnforcementError(f"No ping summary for {host.name} -> {destination_ip}: {raw}")
    sent, received, loss = match.groups()
    average = PING_RTT.search(raw)
    return {"sent": int(sent), "received": int(received), "loss": int(loss), "rtt_ms": float(average.group(1)) if average else None, "raw": raw.strip()}


class MininetAuthorizer:
    """Temporarily blocks denied ICMP requests at their originating namespace.

    This makes a policy denial observable on the real Mininet data plane while
    keeping the Phase 1 topology unchanged. The rule is removed immediately.
    """
    def __init__(self, iptables_executable: str = IPTABLES_EXECUTABLE):
        self.iptables_executable = iptables_executable

    def _iptables_command(self, action: str, destination_ip: str) -> str:
        return f"{self.iptables_executable} {action} OUTPUT -d {destination_ip} -p icmp -j DROP"

    def execute(self, host, destination_ip: str, allowed: bool) -> tuple[dict, str]:
        if allowed:
            result = ping(host, destination_ip)
            if result["received"] == 0: raise EnforcementError(f"Allowed request unexpectedly failed: {host.name} -> {destination_ip}: {result['raw']}")
            return result, "none"
        add_output = host.cmd(self._iptables_command("-I", destination_ip))
        if add_output.strip(): raise EnforcementError(f"Could not install deny rule for {host.name}: {add_output}")
        try:
            result = ping(host, destination_ip)
            if result["received"] != 0: raise EnforcementError(f"Denied request reached {destination_ip}: {result['raw']}")
            return result, "iptables_output_icmp_drop"
        finally:
            host.cmd(self._iptables_command("-D", destination_ip))
