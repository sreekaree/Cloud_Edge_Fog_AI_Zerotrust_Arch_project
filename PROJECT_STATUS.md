# MedTrustEdge — AI-Driven Blockchain-Enabled Zero Trust Architecture for Secure Healthcare Cloud–Fog–Edge Computing

## Project Status & Checkpoint

**Date:** 2026-09-25  
**Workspace:** `CN`  

---

### 1. Project Overview
**MedTrustEdge** is a research framework investigating an AI-driven, blockchain-enabled Zero Trust architecture for secure healthcare Cloud–Fog–Edge computing. The system integrates multi-tenant IoMT traffic generation, software-defined networking (Mininet / Open vSwitch), deterministic Zero Trust policy enforcement, and downstream machine learning anomaly detection.

---

### 2. Phase 1 Status: COMPLETE
- **Description:** Real Mininet / Open vSwitch networking baseline executed and validated.
- **Components:**
  - Synthetic IoMT devices across two independent healthcare tenants (Hospital A, Hospital B) and a shared Cloud server.
  - Multi-layer topology with named Open vSwitch segments (`swA_access`, `swA_edge_fog`, `swA_fog_cloud`, `swB_access`, `swB_edge_fog`, `swB_fog_cloud`, `sw_baseline_a`, `sw_baseline_b`).
  - Fallback simulation measurements and verified real Mininet ICMP probe evaluations.
- **Preservation:** Existing Phase 1 results (`results/fallback/`, `results/mininet/`) and generated plots (`plots/`) are preserved.

---

### 3. Phase 2 Status: COMPLETE
- **Description:** Real Mininet Zero Trust policy enforcement experiment completed.
- **Request Breakdown (25 total requests):**
  - **20 ALLOW** (authorized tenant-local telemetry across Edge, Fog, and Cloud)
  - **5 DENY** (cross-tenant access, unauthorized service/port, revoked identity, suspicious state, expired temporary privilege)
- **Current Verified Summary Metrics (`results/zerotrust/zerotrust_summary.csv`):**
  - `requests`: 25
  - `allowed`: 20
  - `denied`: 5
  - `mean_allowed_network_rtt_ms`: 62.86365 ms
  - `mean_policy_decision_latency_ms`: 0.021479 ms
  - `cpu_utilization`: 0.0
  - `memory_utilization`: 13.4
  - `security_events`: 25
- **Enforcement & Audit:**
  - Denials verified via temporary `/usr/sbin/iptables` OUTPUT rules in Mininet namespaces.
  - Complete security audit log captured in `results/zerotrust/zerotrust_security_events.csv` and `.jsonl`.

---

### 4. Phase 3A Status: COMPLETE
- **Description:** AI data and feature pipeline constructed. **No AI model was trained.**
- **Provenance & Derivation:** The dataset was derived strictly from the preserved, real Phase 2 audit events (`results/zerotrust/zerotrust_security_events.csv`).
- **Artifacts:**
  - **Dataset:** `results/ai/phase3a_iomt_anomaly_dataset.csv`
  - **Schema:** `results/ai/phase3a_feature_schema.json`
  - **Provenance Manifest:** `results/ai/phase3a_manifest.json`
- **Dataset Composition:**
  - **Total Records:** 25
  - **Normal Records:** 20
  - **Anomalous Records:** 5
- **Validation:**
  - **18/18 unit tests passed** across the complete test suite (`tests/`).

---

### 5. Phase 3A Pipeline Flow
```text
Real Phase 2 Audit CSV (results/zerotrust/zerotrust_security_events.csv)
  │
  ▼
Deterministic Feature Extraction (src/ai/feature_extraction.py)
  │
  ▼
Scenario-Based Labels (config/ai_feature_pipeline.yaml)
  │
  ▼
AI Dataset (results/ai/phase3a_iomt_anomaly_dataset.csv)
  │
  ├──► Feature Schema (results/ai/phase3a_feature_schema.json)
  └──► SHA-256 Provenance Manifest (results/ai/phase3a_manifest.json)
```

---

### 6. Explicit Limitations
- **Unmeasured Network Attributes:** Bytes transferred and TCP-specific flags/values were not measured in the ICMP probe architecture and were intentionally excluded rather than inferred.
- **No Synthetic or Live Collection in Phase 3A:** No synthetic records were fabricated, and no new live Mininet collection runs were executed for Phase 3A.
- **Pending Controlled Scenarios:** Scenarios such as elevated request rate and repeated service probes are configured for future real Mininet collection only.
- **Out of Scope for Current State:**
  - No blockchain functionality exists yet.
  - No adaptive orchestration functionality exists yet.
  - No trained AI model exists yet.

---

### 7. Next Planned Phase: Phase 3B (AI Anomaly Detection Model)
**Objective:** Train and evaluate an AI anomaly detection model using the validated Phase 3A dataset.

**Mandatory Pre-Training Inspection Requirements:**
Before training commences, Phase 3B must first inspect:
1. The complete Phase 3A CSV dataset (`results/ai/phase3a_iomt_anomaly_dataset.csv`).
2. All 24 schema fields defined in `results/ai/phase3a_feature_schema.json`.
3. Class distribution (current 20:5 normal-to-anomalous ratio).
4. Categorical vs. numerical feature encodings.
5. Potential label leakage (e.g., verifying whether decision or scenario fields must be withheld from model training inputs).
6. Appropriate train/test split methodology suitable for small-sample, high-fidelity experimental data.

*Model Selection Note:* Random Forest is the planned initial candidate model because it is interpretable and suitable for resource-constrained edge/fog nodes, but this must NOT be treated as final until the dataset inspection is completed.

---

### 8. Freezing Policy
> **"Phase 3A is frozen and should not be regenerated unless a reproducibility problem is discovered."**
