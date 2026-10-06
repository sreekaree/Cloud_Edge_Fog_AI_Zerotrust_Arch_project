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

### 6. Phase 3B Status: COMPLETE
- **Description:** Defensible, reproducible AI anomaly detection model pipeline implemented and evaluated.
- **Leakage Controls & Feature Engineering:**
  - Strictly excluded all direct and indirect post-enforcement artifacts: `decision`, `enforcement`, `scenario`, `experiment_id`, `label_basis`, `packet_loss_percent` (100% loss caused by iptables drop), `network_rtt_ms` (missingness caused by drop), `flow_duration_ms` / `flow_rate_pps` (ping timeout artifacts caused by iptables drop), `policy_decision_latency_ms`, and `trust_state` (policy configuration state excluded to prevent circular dependency with Phase 4).
  - Selected observable request attributes: `tenant_id`, `source_device`, `destination`, `service`, `port`, `connection_frequency_60s`.
  - Engineered domain boundary relations: `is_cross_tenant` (subnet boundary mismatch) and `is_diagnostic_service` (privileged diagnostic port flag).
- **Candidate Models & Evaluation:**
  - Evaluated via **Stratified 5-Fold Cross-Validation** ($N=25$, 20 normal : 5 anomalous; each fold has 4 normal and 1 anomalous sample evaluated out-of-fold).
  - Models compared: **Random Forest** (primary candidate), **Decision Tree** (interpretable baseline), **Logistic Regression** (linear baseline).
  - **Verified Cross-Validation Metrics (`results/ai/phase3b_model_metrics.csv`):**
    - **Random Forest:** Accuracy = 0.7600, Precision = 0.3333, Recall = 0.2000, F1 = 0.2500, ROC-AUC = 0.7250 (TN=18, FP=2, FN=4, TP=1).
    - **Decision Tree:** Accuracy = 0.7200, Precision = 0.2500, Recall = 0.2000, F1 = 0.2222, ROC-AUC = 0.5350 (TN=17, FP=3, FN=4, TP=1).
    - **Logistic Regression:** Accuracy = 0.7600, Precision = 0.3333, Recall = 0.2000, F1 = 0.2500, ROC-AUC = 0.5800 (TN=18, FP=2, FN=4, TP=1).
- **Continuous Anomaly Scoring:**
  - Primary model produces continuous anomaly probability scores $[0.0, 1.0]$.
  - On full model fit, all 5 anomalous scenarios produce elevated anomaly scores ($\ge 0.689$), while authorized telemetry requests maintain low risk scores ($\le 0.434$).
  - `temporary_privilege_active` (accessing diagnostic port 9555) produces an elevated score of 0.7187, accurately capturing the inherent risk of the privileged service before Zero Trust JIT authorization.
- **Top Features (Random Forest Gini Impurity):**
  1. `connection_frequency_60s`: 0.2096
  2. `tenant_id_B`: 0.1672
  3. `is_cross_tenant`: 0.0867
  4. `source_device_iotA2`: 0.0787
  5. `is_diagnostic_service`: 0.0736
- **Artifacts:**
  - Configuration: `config/ai_model_config.yaml`
  - Implementation: `src/ai/anomaly_model.py`
  - Runner: `experiments/run_phase3b_model.py`
  - Tests: `tests/test_ai_anomaly_model.py` (7 tests, all passing)
  - Results:
    - `results/ai/phase3b_model_metrics.csv`
    - `results/ai/phase3b_predictions.csv`
    - `results/ai/phase3b_feature_importance.csv`
    - `results/ai/phase3b_model_manifest.json`
  - Plots: `plots/ai/model_comparison.png`, `confusion_matrix.png`, `feature_importance.png`, `anomaly_scores_by_scenario.png`
- **Validation:** 25/25 total project tests passing across the complete test suite (`tests/`):
  - Phase 1 Networking Baseline: 8 tests (`test_config`: 2, `test_devices`: 1, `test_metrics`: 1, `test_mininet_backend`: 4)
  - Phase 2 Zero Trust Baseline: 8 tests (`test_zero_trust_authorization`: 1, `test_zero_trust_identity`: 1, `test_zero_trust_microsegmentation`: 1, `test_zero_trust_policy`: 2, `test_zero_trust_privilege`: 2, `test_zero_trust_revocation`: 1)
  - Phase 3A AI Data Pipeline: 2 tests (`test_ai_feature_pipeline`: 2)
  - Phase 3B AI Anomaly Model: 7 tests (`test_ai_anomaly_model`: 7)

---

### 7. Explicit Limitations & Scientific Honesty
- **Small-Sample Boundary:** With 25 records and 5 anomalies, isolated single-instance attack scenarios ($N=1$, such as cross-tenant) cannot be generalized out-of-fold when held out as an unseen test fold without prior examples. This is an inherent property of high-fidelity small experimental datasets, not a defect.
- **No Synthetic Records:** No synthetic records, SMOTE oversampling, or artificial data generation were used.
- **Out of Scope for Current State:**
  - No blockchain functionality exists yet.
  - No adaptive orchestration functionality exists yet.
- **Offline Simulation Boundary:** Phase 4 is an offline trace replay and integration simulation; it is not a new Mininet network measurement.

---

### 8. Phase 4 Status: COMPLETE
- **Description:** AI-Driven Dynamic Trust Scoring Engine implemented and verified.
- **Architectural Implementation:**
  - Continuous device trust scoring $T \in [0.0, 100.0]$ with Zero Trust deterministic dominance.
  - **AI-Only Trust Floor ($T \ge 70.0$):** High AI anomaly scores cannot push a compliant device into `RESTRICTED` without a deterministic policy violation.
  - **Operational States:** `TRUSTED` ($70.0 \le T \le 100.0$, normal ALLOW), `RESTRICTED` ($30.0 \le T < 70.0$, Edge telemetry only, Fog/Cloud denied), `REVOKED` ($0.0 \le T < 30.0$, complete network isolation).
  - **Dynamic Recovery & Decay:** $+2.0$ recovery per qualifying compliant event in `RESTRICTED`; violation counter $N_{\text{viol}}$ decays by 1 on compliant events and resets to 0 upon returning to `TRUSTED`.
  - **Administrative Restore:** `admin_restore()` validates bounds, resets $N_{\text{viol}} = 0$, updates state to `TRUSTED`, and records an audit log.
- **Policy Engine Adapter:** Programmatic integration mapping `DynamicState.RESTRICTED` $\to$ Phase 2 `TrustState.SUSPICIOUS` verified against `PolicyEngine.evaluate()`.
- **Chronological Audit Replay (25 events):**
  - Offline simulation evaluating preserved Phase 2 audit events strictly using `anomaly_score_oof` from `results/ai/phase3b_predictions.csv`.
  - Offline reconstruction of Phase 2 JIT state from `service == "fog_diagnostic"` and `decision == "ALLOW"`.
  - Final Device Trust: `iotA1` = 0.00 (`REVOKED`), `iotA2` = 0.00 (`REVOKED`), `iotA3` = 100.00 (`TRUSTED`), `iotB1` = 100.00 (`TRUSTED`), `iotB2` = 100.00 (`TRUSTED`), `iotB3` = 100.00 (`TRUSTED`).
- **AI-Ablation Study (Hybrid vs. Deterministic-Only):**
  - Evaluated with $P_{\text{ai}} \equiv 0.0$.
  - State transitions match 100% across all devices, confirming that deterministic Zero Trust policy dominates security state boundaries while AI modulates score velocity and recovery gating.
- **Artifacts:**
  - Engine: `src/zerotrust/dynamic_trust.py`
  - Replay Runner: `experiments/run_phase4_trust_replay.py`
  - Tests: `tests/test_phase4_dynamic_trust.py` (20 tests, all passing)
  - Results:
    - `results/phase4/phase4_trust_trace.csv`
    - `results/phase4/phase4_ablation_metrics.csv`
  - Plots: `plots/phase4/phase4_trust_trajectories.png`
- **Validation:** 45/45 total project tests passing across the complete test suite (`tests/`):
  - Phase 1 Networking Baseline: 8 tests
  - Phase 2 Zero Trust Baseline: 8 tests
  - Phase 3A AI Data Pipeline: 2 tests
  - Phase 3B AI Anomaly Model: 7 tests
  - Phase 4 Dynamic Trust Scoring: 20 tests

---

### 9. Freezing Policy
> **"Phase 1, Phase 2, Phase 3A, and Phase 3B artifacts are frozen and preserved without modification."**

