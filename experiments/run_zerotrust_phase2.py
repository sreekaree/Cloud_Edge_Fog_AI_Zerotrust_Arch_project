"""Run deterministic Phase 2 Zero Trust experiments on real Mininet/OVS."""
import csv
from datetime import datetime, timezone
from pathlib import Path
import sys
import time
import psutil

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from src.topology.mininet_topology import build_network, configure_addresses, mininet_is_available
from src.zerotrust.authorization import MininetAuthorizer
from src.zerotrust.policy_engine import PolicyEngine, PolicyRequest
from src.zerotrust.revocation import revoke_device, restore_device
from src.zerotrust.security_events import SecurityEventLog
from src.zerotrust.trust_state import TrustState

RESULTS = ROOT / "results" / "zerotrust"
PLOTS = ROOT / "plots" / "zerotrust"
POLICY = ROOT / "config" / "zero_trust_policy.yaml"


def resource(engine, key): return engine.config["resources"][key]


def request(engine, authorizer, log, hosts, device_id, resource_key, scenario):
    identity = engine.registry.get(device_id); target = resource(engine, resource_key)
    started = time.perf_counter()
    decision = engine.evaluate(PolicyRequest(device_id, target["destination_ip"], target["service"], target["port"]))
    network, enforcement = authorizer.execute(hosts[device_id], target["destination_ip"], decision.decision == "ALLOW")
    event = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(), "scenario": scenario,
        "device_id": device_id, "tenant_id": identity.tenant_id, "source_ip": identity.ip_address,
        "destination": resource_key, "destination_ip": target["destination_ip"], "service": target["service"], "port": target["port"],
        "decision": decision.decision, "reason": decision.reason, "trust_state": identity.trust_state.value,
        "policy_id": decision.policy_id, "policy_decision_latency_ms": round(decision.decision_latency_ms, 6),
        "network_rtt_ms": network["rtt_ms"], "total_request_latency_ms": round((time.perf_counter() - started) * 1000, 6),
        "packet_loss_percent": network["loss"], "enforcement": enforcement,
    }
    log.record(event); print(f"{scenario}: {device_id} -> {resource_key}: {decision.decision} ({decision.reason})")
    return event


def write_measurements(events):
    RESULTS.mkdir(parents=True, exist_ok=True)
    groups = {"edge": "zerotrust_edge_latency.csv", "fog": "zerotrust_fog_latency.csv", "cloud": "zerotrust_cloud_latency.csv"}
    for group, filename in groups.items():
        rows = [event for event in events if event["scenario"] == f"authorized_{group}"]
        if rows:
            with (RESULTS / filename).open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=rows[0].keys()); writer.writeheader(); writer.writerows(rows)
    allowed = sum(event["decision"] == "ALLOW" for event in events); denied = len(events) - allowed
    fields = ("requests", "allowed", "denied", "mean_allowed_network_rtt_ms", "mean_policy_decision_latency_ms", "cpu_utilization", "memory_utilization", "security_events")
    allowed_rtt = [event["network_rtt_ms"] for event in events if event["decision"] == "ALLOW" and event["network_rtt_ms"] is not None]
    with (RESULTS / "zerotrust_summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader(); writer.writerow({
            "requests": len(events), "allowed": allowed, "denied": denied,
            "mean_allowed_network_rtt_ms": round(sum(allowed_rtt) / len(allowed_rtt), 6) if allowed_rtt else "unavailable",
            "mean_policy_decision_latency_ms": round(sum(event["policy_decision_latency_ms"] for event in events) / len(events), 6),
            "cpu_utilization": round(psutil.cpu_percent(interval=0.2), 2),
            "memory_utilization": round(psutil.virtual_memory().percent, 2),
            "security_events": len(events),
        })
    phase1 = {"edge": ROOT / "results" / "mininet" / "mininet_edge_latency.csv", "fog": ROOT / "results" / "mininet" / "mininet_fog_latency.csv", "cloud": ROOT / "results" / "mininet" / "mininet_end_to_end_latency.csv"}
    with (RESULTS / "zerotrust_phase1_comparison.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ("path", "phase1_mean_rtt_ms", "zerotrust_mean_rtt_ms", "phase1_source", "zerotrust_source")
        writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader()
        for path, source in phase1.items():
            phase1_rows = list(csv.DictReader(source.open(encoding="utf-8"))) if source.exists() else []
            phase1_mean = sum(float(row["mean_rtt_ms"]) for row in phase1_rows) / len(phase1_rows) if phase1_rows else "unavailable"
            zt_rows = [event for event in events if event["scenario"] == f"authorized_{path}"]
            zt_mean = sum(event["network_rtt_ms"] for event in zt_rows) / len(zt_rows) if zt_rows else "unavailable"
            writer.writerow({"path": path, "phase1_mean_rtt_ms": phase1_mean, "zerotrust_mean_rtt_ms": zt_mean, "phase1_source": str(source.relative_to(ROOT)) if phase1_rows else "unavailable", "zerotrust_source": f"zerotrust_{path}_latency.csv" if zt_rows else "unavailable"})


def make_plots():
    """Plot only rows already persisted from the successful real experiment."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    PLOTS.mkdir(parents=True, exist_ok=True)
    with (RESULTS / "zerotrust_policy_decisions.csv").open(newline="", encoding="utf-8") as stream:
        events = list(csv.DictReader(stream))
    categories = ["authorized_edge", "authorized_fog", "authorized_cloud"]
    rtts = [sum(float(event["network_rtt_ms"]) for event in events if event["scenario"] == scenario) / sum(event["scenario"] == scenario for event in events) for scenario in categories]
    plt.figure(figsize=(7, 4)); plt.bar(["Edge", "Fog", "Cloud"], rtts); plt.ylabel("RTT (ms)"); plt.title("Phase 2 Zero Trust allowed-request RTT"); plt.tight_layout(); plt.savefig(PLOTS / "zerotrust_latency_by_layer.png", dpi=150); plt.close()
    allowed = sum(event["decision"] == "ALLOW" for event in events); denied = len(events) - allowed
    plt.figure(figsize=(5, 4)); plt.bar(["ALLOW", "DENY"], [allowed, denied]); plt.ylabel("Requests"); plt.title("Zero Trust policy decisions"); plt.tight_layout(); plt.savefig(PLOTS / "zerotrust_allowed_denied.png", dpi=150); plt.close()
    plt.figure(figsize=(7, 4)); plt.bar(range(len(events)), [float(event["policy_decision_latency_ms"]) for event in events]); plt.ylabel("Policy decision latency (ms)"); plt.title("Deterministic policy evaluation latency"); plt.tight_layout(); plt.savefig(PLOTS / "zerotrust_policy_latency.png", dpi=150); plt.close()


def main():
    if not mininet_is_available(): raise SystemExit("Mininet unavailable: Phase 2 produces no results without a real Mininet run.")
    engine = PolicyEngine.from_config(POLICY); authorizer = MininetAuthorizer(); log = SecurityEventLog(RESULTS)
    net, hosts = build_network(); net.start()
    try:
        configure_addresses(net)
        # Experiments 1–3: actual allowed traffic over the original tenant paths.
        events = []
        for device_id in sorted(hosts):
            tenant = "a" if device_id.startswith("iotA") else "b"
            events.extend((
                request(engine, authorizer, log, hosts, device_id, f"edge_{tenant}", "authorized_edge"),
                request(engine, authorizer, log, hosts, device_id, f"fog_{tenant}", "authorized_fog"),
                request(engine, authorizer, log, hosts, device_id, f"cloud_{tenant}", "authorized_cloud"),
            ))
        # Experiments 4–8: denials are enforced with a temporary namespace rule and verified by ping loss.
        events.append(request(engine, authorizer, log, hosts, "iotA1", "edge_b", "cross_tenant"))
        events.append(request(engine, authorizer, log, hosts, "iotA1", "edge_a", "revocation_before"))
        revoke_device(engine.registry, "iotA1"); events.append(request(engine, authorizer, log, hosts, "iotA1", "edge_a", "revocation_after")); restore_device(engine.registry, "iotA1")
        events.append(request(engine, authorizer, log, hosts, "iotA2", "fog_a_diagnostic", "unauthorized_service"))
        engine.registry.set_trust_state("iotA2", TrustState.SUSPICIOUS); events.append(request(engine, authorizer, log, hosts, "iotA2", "fog_a", "suspicious_state")); engine.registry.set_trust_state("iotA2", TrustState.TRUSTED)
        engine.privileges.grant("iotA2", "fog_diagnostic"); events.append(request(engine, authorizer, log, hosts, "iotA2", "fog_a_diagnostic", "temporary_privilege_active")); engine.privileges.revoke("iotA2", "fog_diagnostic"); events.append(request(engine, authorizer, log, hosts, "iotA2", "fog_a_diagnostic", "temporary_privilege_removed"))
        log.write(); write_measurements(events); make_plots()
        print(f"Zero Trust results written to {RESULTS}")
    finally: net.stop()


if __name__ == "__main__": main()
