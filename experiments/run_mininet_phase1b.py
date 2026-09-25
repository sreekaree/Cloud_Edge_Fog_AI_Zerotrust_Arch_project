"""Execute real Phase 1B Mininet measurements (Linux/WSL + root required)."""
import csv
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from src.topology.mininet_topology import (
    MEASUREMENT_DESTINATIONS,
    build_network,
    configure_addresses,
    mininet_is_available,
)

RESULTS = ROOT / "results" / "mininet"
SUMMARY_PATTERN = re.compile(r"(\d+) packets transmitted, (\d+) received,.*?(\d+)% packet loss", re.S)
RTT_PATTERN = re.compile(r"= [^/]+/([^/]+)/")


class ConnectivityError(RuntimeError):
    """A real topology failure, including the command output needed to diagnose it."""

def ping_measure(source, destination_ip, destination, count=5):
    raw = source.cmd(f"ping -c {count} -q {destination_ip}")
    match = SUMMARY_PATTERN.search(raw)
    if not match:
        raise ConnectivityError(f"Ping summary was unavailable for {source.name} -> {destination_ip}. Raw output:\n{raw}")
    sent, received, loss = match.groups()
    if int(received) == 0:
        raise ConnectivityError(f"Connectivity failure: {source.name} cannot reach {destination} ({destination_ip}); {loss}% packet loss. Raw output:\n{raw}")
    average_match = RTT_PATTERN.search(raw)
    if not average_match:
        raise ConnectivityError(f"Ping reached {destination_ip}, but RTT statistics were unavailable. Raw output:\n{raw}")
    average = average_match.group(1)
    return {"source": source.name, "destination": destination, "destination_ip": destination_ip, "packets_sent": sent, "packets_received": received, "packet_loss_percent": loss, "mean_rtt_ms": average, "raw_output": raw.strip()}

def write(name, rows):
    RESULTS.mkdir(parents=True, exist_ok=True)
    with (RESULTS / name).open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys()); writer.writeheader(); writer.writerows(rows)


def tenant_for(name): return "A" if name.startswith("iotA") else "B"


def print_inventory(nodes):
    print("\n=== Host/interface/IP inventory ===")
    for name in sorted(nodes):
        print(f"{name}: {nodes[name].cmd('ip -o -4 addr show').strip()}")


def probe(source, destination_ip, label):
    raw = source.cmd(f"ping -c 1 -W 2 -q {destination_ip}")
    summary = SUMMARY_PATTERN.search(raw)
    received = int(summary.group(2)) if summary else 0
    status = "PASS" if received else "FAIL"
    print(f"{status}: {label} ({source.name} -> {destination_ip})")
    return status == "PASS", raw


def verify_connectivity(nodes, devices):
    """Print the required matrix before writing any experimental measurements."""
    print("\n=== Pre-measurement connectivity matrix ===")
    checks = []
    for name, host in devices.items():
        tenant = tenant_for(name)
        checks.append(probe(host, MEASUREMENT_DESTINATIONS["edge"][tenant], f"{name} -> tenant Edge"))
    checks.extend((
        probe(nodes["edgeA"], MEASUREMENT_DESTINATIONS["fog"]["A"], "edgeA -> fogA"),
        probe(nodes["edgeB"], MEASUREMENT_DESTINATIONS["fog"]["B"], "edgeB -> fogB"),
        probe(nodes["fogA"], MEASUREMENT_DESTINATIONS["cloud"]["A"], "fogA -> cloud1"),
        probe(nodes["fogB"], MEASUREMENT_DESTINATIONS["cloud"]["B"], "fogB -> cloud1"),
    ))
    for name, host in devices.items():
        tenant = tenant_for(name)
        checks.append(probe(host, MEASUREMENT_DESTINATIONS["cloud"][tenant], f"{name} -> cloud routed path"))
        checks.append(probe(host, MEASUREMENT_DESTINATIONS["cloud_baseline"][tenant], f"{name} -> cloud baseline"))
    failures = [raw for passed, raw in checks if not passed]
    if failures:
        raise ConnectivityError(f"Pre-measurement matrix has {len(failures)} failed checks. No latency CSVs were written. First failure:\n{failures[0]}")

def main():
    if not mininet_is_available(): raise SystemExit("Mininet unavailable. See README for Linux/WSL installation steps; no measurements were run.")
    net, devices = build_network(); net.start()
    try:
        nodes = configure_addresses(net)
        print_inventory(nodes)
        verify_connectivity(nodes, devices)
        # These invoke actual ICMP traffic on emulated interfaces; raw command output is persisted.
        edge = [ping_measure(host, MEASUREMENT_DESTINATIONS["edge"][tenant_for(name)], "edge") for name, host in devices.items()]
        fog = [ping_measure(host, MEASUREMENT_DESTINATIONS["fog"][tenant_for(name)], "fog") for name, host in devices.items()]
        cloud = [ping_measure(host, MEASUREMENT_DESTINATIONS["cloud"][tenant_for(name)], "cloud") for name, host in devices.items()]
        baseline = [ping_measure(host, MEASUREMENT_DESTINATIONS["cloud_baseline"][tenant_for(name)], "cloud_baseline") for name, host in devices.items()]
        write("mininet_edge_latency.csv", edge); write("mininet_fog_latency.csv", fog); write("mininet_end_to_end_latency.csv", cloud); write("mininet_cloud_baseline.csv", baseline)
        print("Real Mininet measurements saved to", RESULTS)
    finally: net.stop()
if __name__ == "__main__": main()
