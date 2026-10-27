# MedTrustEdge — Phase 1A and Phase 1B

MedTrustEdge is a research prototype for a Cloud–Fog–Edge healthcare architecture. Phase 1 supplies only its reproducible networking foundation: synthetic IoMT traffic, two healthcare tenants, logical routing, latency/throughput/loss measurements, CSV exports, and plots.

It **does not implement AI, blockchain, Zero Trust, trust scoring, anomaly/attack detection, federated learning, or orchestration**. Those remain deliberately outside this phase.

## Architecture and addressing

Each hospital has three synthetic devices flowing through a dedicated Edge node and Fog node to the shared Cloud server:

```text
IoMT device -> tenant Edge -> tenant Fog -> shared Cloud
```

| Tenant | IoMT subnet | Edge | Fog |
|---|---|---|---|
| Hospital A | `10.1.1.0/24` | `10.1.2.10` | `10.1.3.10` |
| Hospital B | `10.2.1.0/24` | `10.2.2.10` | `10.2.3.10` |
| Shared Cloud | — | — | `10.10.0.10` |

Devices cover ECG, blood pressure, SpO2, and temperature. Their priority is metadata only. Packets are fully synthetic and contain no patient information.

## Install and run

Requires Python 3.10+, PyYAML, and matplotlib:

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python experiments/run_phase1.py
```

Configuration, including duration, packet size, intervals, link propagation delays, bandwidths, losses, and tenant devices, lives in `config/network_config.yaml`.

## Outputs and interpretation

The run creates `results/fallback/edge_latency.csv`, `fog_latency.csv`, `end_to_end_latency.csv`, `cloud_latency.csv`, and `baseline_comparison.csv`, plus plots in `plots/`. Each row includes generation timestamp, device/type/tenant, destination, packet size/count, latency, effective throughput, and packet loss.

`cloud_latency.csv` is the centralized **IoMT → Cloud** baseline. The end-to-end result is **IoMT → Edge → Fog → Cloud**. Compare them only under the configured simulation conditions; they are not a general performance claim.

## Execution modes and limitations

The runner detects Mininet. On systems without it (including typical Windows installations), it runs the clearly labeled fallback logical simulator. That simulator computes measurements from configured propagation, serialization, and processing delays, with seeded loss; it does not create Linux namespaces, Open vSwitch flows, or real packets. It must never be reported as Mininet execution.

## Phase 1B: real Mininet + Open vSwitch backend

The Phase 1B backend is in `src/topology/mininet_topology.py` and uses named Open vSwitch segments, six IoMT hosts (`iotA1`–`iotA3`, `iotB1`–`iotB3`), Edge routers (`edgeA`, `edgeB`), Fog routers (`fogA`, `fogB`), and `cloud1`. The eight named switches have deterministic explicit DPIDs `0000000000000001` through `0000000000000008`; this avoids Mininet's canonical-name DPID derivation requirement while keeping descriptive switch names.

Linux limits interface names to 15 visible characters, while Mininet generates them as `<node>-ethN`. Therefore the following internal Mininet bridge aliases are used; the logical switch names and their roles remain unchanged:

| Logical switch | Mininet bridge name |
|---|---|
| `swA_access` | `swaacc` |
| `swA_edge_fog` | `swaef` |
| `swA_fog_cloud` | `swafc` |
| `swB_access` | `swbacc` |
| `swB_edge_fog` | `swbef` |
| `swB_fog_cloud` | `swbfc` |
| `sw_baseline_a` | `sbasea` |
| `sw_baseline_b` | `sbaseb` |

The routed data path is:

```text
Tenant A: iotA* -> swA_access -> edgeA -> swA_edge_fog -> fogA -> swA_fog_cloud -> cloud1
Tenant B: iotB* -> swB_access -> edgeB -> swB_edge_fog -> fogB -> swB_fog_cloud -> cloud1
```

Separate baseline-only OVS segments attach the IoMT hosts directly to cloud interfaces for a controlled IoMT → Cloud measurement. Tenant A and B primary paths remain separate L2/L3 segments; this is structural separation only, **not** Zero Trust.

Because this topology deliberately uses no OpenFlow controller, each OVS bridge is created in `standalone` fail mode. This enables normal bridge MAC learning for the configured access and transit segments; secure mode with no controller would otherwise leave those segments without forwarding flows.

Run only from Linux or a functioning WSL distribution with administrator/root privileges:

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch iperf3
sudo systemctl enable --now openvswitch-switch
cd /path/to/MedTrustEdge
sudo python3 experiments/run_mininet_phase1b.py
```

The runner uses actual ICMP traffic in Mininet namespaces and records parsed RTT and loss plus raw ping output in `results/mininet/`. It does not create fallback values if Mininet is unavailable. Add `iperf3` for future throughput experiments; Phase 1B currently measures RTT and packet loss only, so it makes no unverified throughput claim.

### Results separation

Phase 1A and Phase 1B results are intentionally separate:

- `results/fallback/` contains configured logical-simulation timing results. The PNG files in `plots/` were generated from this fallback output.
- `results/mininet/` contains raw, real Mininet ICMP measurements from the WSL experiment. It contains four CSV files and no logical-simulation rows.

The saved Phase 1B run measured all six IoMT hosts five times per scenario (30 ICMP probes per scenario), with 0% packet loss. Its six-host mean RTTs were 8.976 ms (Edge), 43.470 ms (Fog), 147.827 ms (routed Edge–Fog–Cloud), and 188.051 ms (cloud-only baseline). See `PHASE1_RESULTS.md` for the complete auditable summary. There are currently no Mininet-specific plots; the existing PNGs must not be interpreted as real-emulation plots.

Phase 2 security or intelligence components have **not** been implemented. Future Phase 2 work may only begin after controlled network-baseline experiments are completed.

## Phase 2 — Zero Trust Baseline

Phase 2 adds a deterministic, configuration-driven Zero Trust policy layer while preserving the Phase 1 topology and result files. The policy is defined in `config/zero_trust_policy.yaml`; it registers the six IoMT identities with their tenant, device type, IP address, identity and authorization status, allowed services, and current trust state.

Every request is evaluated against the configured identity, tenant, destination IP, service/port, authorization state, policy state, and current trust state. Decisions are deterministic `ALLOW` or `DENY`. `TRUSTED` devices may use configured telemetry services, `SUSPICIOUS` devices are limited to Edge telemetry, and `REVOKED` devices are denied. A temporary, in-memory just-in-time grant can permit the Fog diagnostic service until the grant is explicitly removed.

For a real Mininet run, denied ICMP experiment requests are temporarily blocked in the originating Mininet namespace with a `/usr/sbin/iptables` OUTPUT rule, then verified with packet loss before the rule is removed. The absolute executable path avoids namespace `PATH` differences on Ubuntu/WSL. This makes policy denial observable without changing the Phase 1 switches, routes, or links. The event log is ordinary local CSV/JSONL audit data; it is not blockchain.

Run Phase 2 only in the verified Linux/WSL Mininet environment:

```bash
sudo mn -c
sudo python3 experiments/run_zerotrust_phase2.py
```

On a successful real run, the following are written without overwriting Phase 1 results:

- `results/zerotrust/zerotrust_edge_latency.csv`
- `results/zerotrust/zerotrust_fog_latency.csv`
- `results/zerotrust/zerotrust_cloud_latency.csv`
- `results/zerotrust/zerotrust_policy_decisions.csv`
- `results/zerotrust/zerotrust_security_events.csv` and `.jsonl`
- `results/zerotrust/zerotrust_summary.csv`
- `results/zerotrust/zerotrust_phase1_comparison.csv`
- `plots/zerotrust/` charts generated only from that run's actual results

The comparison file reports Phase 1 Mininet RTTs from their preserved CSVs beside measured Zero Trust RTTs. CPU and memory fields are explicitly `unavailable` in Phase 2 because this runner does not collect them reliably.

Phase 2 does **not** implement AI, blockchain, trust scoring by AI, authentication protocols, authorization frameworks beyond this deterministic policy baseline, or adaptive orchestration. Those remain later research phases.

## Phase 3A — AI Data and Feature Pipeline

Phase 3A prepares the reproducible dataset required before training an anomaly-detection model. It does **not** train, evaluate, or claim a final AI model. The pipeline reads the preserved real Phase 2 Mininet audit log (`results/zerotrust/zerotrust_security_events.csv`) and writes derived data to `results/ai/`; it never changes Phase 1 or Phase 2 measurements.

Collected features are the source device, tenant and addresses, destination/service/port, protocol (`ICMP`), five-packet probe count, observed flow duration, derived flow rate, 60-second connection frequency, observed RTT when available, packet loss, policy decision latency, decision, trust state, enforcement method, scenario, and deterministic label. Bytes transferred, TCP flags, and other unobserved packet-level values are intentionally excluded rather than estimated.

The labels describe controlled experimental scenarios, not real-world attack ground truth. Authorized tenant-local monitoring, revocation-before, and active temporary privilege requests are `normal`. Controlled cross-tenant access, revoked identity, unauthorized service, suspicious state, and expired privilege requests are `anomalous`. Possible controlled future collection scenarios—such as elevated request frequency or repeated service probes—are documented in `config/ai_feature_pipeline.yaml` but are not added to the dataset until genuinely observed in Mininet.

Run the pipeline after a real Phase 2 run:

```bash
python3 experiments/run_phase3a_pipeline.py
```

It writes `phase3a_iomt_anomaly_dataset.csv`, a feature-schema JSON file, and a source/dataset hash manifest to `results/ai/`. This phase contains no blockchain or adaptive orchestration functionality.

## Phase 3B — AI Anomaly Detection Model

Phase 3B trains and evaluates an anomaly detection model using the frozen Phase 3A dataset. To ensure scientific defensibility, it enforces strict leakage controls: all post-enforcement artifacts (iptables packet drop loss, ping timeout durations, missing RTT values) and policy engine decisions are withheld from model inputs.

Input features comprise observable request attributes (`tenant_id`, `source_device`, `destination`, `service`, `port`, `connection_frequency_60s`) and engineered domain relations (`is_cross_tenant`, `is_diagnostic_service`).

Candidate models (Random Forest, Decision Tree, Logistic Regression) are evaluated via Stratified 5-Fold Cross-Validation. In addition to discrete classifications, the models generate continuous anomaly probability scores $[0.0, 1.0]$ for downstream input to the Phase 4 Zero Trust dynamic trust engine.

Run the Phase 3B pipeline:

```bash
python experiments/run_phase3b_model.py
```

Outputs written to `results/ai/`:
- `phase3b_model_metrics.csv` (Cross-validation metrics)
- `phase3b_predictions.csv` (Out-of-fold and full anomaly scores)
- `phase3b_feature_importance.csv` (Feature importances / coefficients)
- `phase3b_model_manifest.json` (Provenance manifest with dataset SHA-256 and hyper-parameters)
- Visualizations in `plots/ai/`

## Phase 4 — AI-Driven Dynamic Trust Scoring Engine

Phase 4 implements continuous, AI-driven dynamic trust scoring ($T \in [0.0, 100.0]$) where deterministic Zero Trust policy enforcement strictly dominates security boundaries while auxiliary out-of-fold AI anomaly scores from Phase 3B modulate trust degradation and recovery velocity.

Key architectural features:
- **AI-Only Trust Floor ($T \ge 70.0$):** High AI anomaly scores cannot push a compliant device into `RESTRICTED` without a deterministic policy violation.
- **Operational Dynamic States:** `TRUSTED` ($70.0 \le T \le 100.0$, normal ALLOW), `RESTRICTED` ($30.0 \le T < 70.0$, Edge telemetry allowed, Fog/Cloud denied), and `REVOKED` ($0.0 \le T < 30.0$, total network isolation).
- **Decay & Recovery:** Compliant events in `RESTRICTED` decay violation counters by 1 and earn $+2.0$ recovery until reaching `TRUSTED`; returning to `TRUSTED` resets $N_{\text{viol}} \leftarrow 0$.
- **Policy Engine Adapter:** Continuous `RESTRICTED` state maps to Phase 2 `TrustState.SUSPICIOUS`, verified against the live `PolicyEngine`.
- **Ablation Arm:** Compares hybrid scoring against a deterministic-only baseline ($P_{\text{ai}} \equiv 0.0$), confirming identical state transitions while quantifying AI risk modulation.

Run the Phase 4 offline replay and ablation experiment:

```bash
python experiments/run_phase4_trust_replay.py
```

Outputs written to `results/phase4/` and `plots/phase4/`:
- `results/phase4/phase4_trust_trace.csv` (25-event chronological audit replay trace)
- `results/phase4/phase4_ablation_metrics.csv` (Hybrid vs Deterministic-only comparative metrics)
- `plots/phase4/phase4_trust_trajectories.png` (Continuous trust score trajectory visualizations)



## Phase 5 — Blockchain Audit Ledger

Phase 5 introduces an immutable, cryptographically verifiable audit ledger for sealing dynamic trust transitions and Zero Trust policy events from Phases 1–4. Using deterministic canonical serialization, SHA-256 event payload hashing, binary Merkle trees, and hash-pointer linkage, Phase 5 guarantees tamper-evident provenance across healthcare IoMT events.

### Architectural Features:
- **Event Adaptation & RFC 8785 Canonical JSON:** Ingests all 21 Phase 4 dynamic trust trace fields, joined strictly on the 16-hex character `record_id` with Phase 2 audit timestamps. Payload serialization enforces sorted keys and compact delimiters.
- **Binary Merkle Trees & Inclusion Proofs:** Computes balanced Merkle roots with terminal leaf duplication for odd node counts. Provides compact logarithmic inclusion proofs ($O(\log_2 B)$) verifying event membership in sealed blocks.
- **Sequential Hash-Linked Ledger:** Genesis block (height 0, 64-zero previous hash, empty root) followed by sequentially sealed blocks with configurable batch size $B$ (default $B=5$).
- **Chain Verifier & Forensic Attribution:** Complete multi-check validation engine inspecting Genesis parameters, block indices, header hashes, previous hash continuity, payload hashes, and Merkle inclusion proofs.
- **Adversarial Tamper Detection Suite:** Evaluates 8 distinct attack scenarios (payload alteration, hash modification, header tampering, broken previous-block pointers, event reordering, block swapping, event deletion, and block deletion). All 8 attacks are detected with 100.0% precision.

> [!IMPORTANT]
> **Single-Node Audit Ledger Scope:**
> Phase 5 implements a local, in-memory Python hash-linked audit ledger. It demonstrates mathematical proof-of-immutability and tamper detection. It does **not** implement distributed consensus (PoW/PoS/PBFT), P2P gossip networks, or multi-node Byzantine fault tolerance.

Run Phase 5 experiments:
```bash
# Tamper detection experiments (8 attack scenarios)
python experiments/run_phase5_tamper_experiments.py

# Multi-repetition performance benchmarking and scaling
python experiments/run_phase5_performance_benchmarks.py

# Phase 5 validation runner
python experiments/run_phase5_final_validation.py
```

Outputs written to `results/phase5/`:
- `phase5_baseline_ledger.json` (Sealed ledger: 6 blocks, 25 events, B=5)
- `phase5_tamper_detection_report.csv` & `summary.json` (8/8 attacks detected)
- `phase5_performance_benchmarks.csv` & `summary.json` (68 benchmark records)
- Diagnostic plots: `phase5_scaling_event_count.png`, `phase5_scaling_batch_size.png`, `phase5_verification_ablation.png`

## Phase 6 — Final Validation, Security Hardening, and Integration

Phase 6 finalizes the MedTrustEdge architecture by hardening the audit ledger against whole-chain rewrite attacks, centralizing configuration, verifying cross-phase lineage, and establishing automated 10-gate validation.

### Hardening Features:
- **Centralized YAML Configuration:** Operational parameters are centralized in `config/blockchain_config.yaml` with strict dataclass type validation (`src/blockchain/config.py`). Rejects invalid parameters fail-fast.
- **External Cryptographic Checkpoints (`src/blockchain/checkpoint.py`):** Solves the single-node whole-chain fork substitution vulnerability. Anchors ledger tips using RFC 8032 Ed25519 asymmetric digital signatures (256-bit seed, Edwards25519 curve) and HMAC-SHA256 symmetric MACs.
- **10-Gate Validation Runner (`experiments/run_phase6_final_validation.py`):** Automated end-to-end audit verifying baseline hashes (Gate 1), configuration (Gate 2), event adaptation (Gate 3), ledger construction (Gate 4), Merkle proofs (Gate 5), tamper detection (Gate 6), checkpoint security (Gate 7), pipeline lineage (Gate 8), run isolation (Gate 9), and performance consistency (Gate 10).
- **Run Isolation & Immutable Manifests:** Every Phase 6 validation execution writes to an isolated directory (`results/phase6/run_<timestamp>_<id>/`) containing an immutable `run_manifest.json` and a comprehensive Markdown report.
- **Unbroken Pipeline Lineage:** Preserves all seven frozen Phase 1–4 golden baseline SHA-256 hashes and confirms 100% record ID derivation continuity from Phase 2 through Phase 6.

### Run Verification:
```powershell
# Run Phase 6 unit and integration tests (20 tests)
python -m unittest discover -s tests -p "test_phase6_*.py" -v

# Run the complete MedTrustEdge test suite (115 tests across Phases 1-6)
python -m unittest discover -s tests -v

# Execute the Phase 6 10-Gate Validation Runner
python experiments/run_phase6_final_validation.py
```
