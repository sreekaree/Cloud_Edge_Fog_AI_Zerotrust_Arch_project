# MedTrustEdge Phase 5 — Blockchain Implementation Specification
**Document Version:** 1.0.0
**Status:** DRAFT FOR REVIEW
**Scope:** Phase 5 — Immutable Zero-Trust Audit Ledger & Verification Engine
**Target Environment:** Cloud–Fog–Edge IoMT Architecture

---

## 1. Objectives & Scope

### 1.1 Problem Statement
In healthcare Cloud–Fog–Edge computing environments, Internet of Medical Things (IoMT) devices transmit safety-critical telemetry across distributed network tiers. While Phase 2 established deterministic Zero Trust policy enforcement and Phase 4 established continuous AI-modulated dynamic trust scoring ($T \in [0.0, 100.0]$), audit logs stored in conventional flat files (e.g., CSV, JSONL) or central databases remain vulnerable to:
1. **Post-facto tampering or log truncation** by compromised edge/fog broker nodes or rogue administrators.
2. **Repudiation of security state transitions** (e.g., denying that a device was transitioned to `RESTRICTED` or `REVOKED`).
3. **Lack of verifiable provenance** linking network telemetry, AI anomaly inferences, deterministic policy decisions, and dynamic trust updates.

### 1.2 Phase 5 Objectives
Phase 5 introduces a lightweight, tamper-evident, decentralized audit ledger tailored for resource-constrained Edge/Fog tiers and centralized Cloud compliance:
- **Cryptographic Immutability:** Anchor chronological security events and trust state transitions using SHA-256 block hashing and binary Merkle tree transaction aggregation.
- **Full Trace Provenance:** Ingest preserved Phase 4 dynamic trust trace records (`results/phase4/phase4_trust_trace.csv`) and Phase 2 security events (`results/zerotrust/zerotrust_security_events.csv`) without altering frozen data.
- **Tamper Detection & Verification:** Implement an automated verification engine capable of detecting single-bit content mutations, event deletions, event insertions, and block header modifications with 100% precision.
- **Tier-Aware Ledger Architecture:** Model multi-tier ledger responsibilities across Edge (event generation & light client verification), Fog (batch aggregation, Merkle root computation, and block sealing), and Cloud (full ledger archival and forensic compliance auditing).
- **Comprehensive Benchmarking & Ablation:** Quantify cryptographic latency (hashing, Merkle tree construction, block sealing) and storage overhead across varying block batch sizes ($B \in \{1, 5, 10, 25\}$).
- **Strict Freezing Compliance:** Ensure zero modification, regeneration, or deletion of Phase 1–4 code, datasets, models, plots, or tests.

---

## 2. Proposed Architecture & Data Flow

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   MedTrustEdge Multi-Tier Flow                              │
├───────────────────────────────┬───────────────────────────────┬─────────────────────────────┤
│          EDGE TIER            │           FOG TIER            │         CLOUD TIER          │
│ (IoMT Devices & Access Gate)  │ (Aggregation & Sealing Node)  │   (Archival & Compliance)   │
├───────────────────────────────┼───────────────────────────────┼─────────────────────────────┤
│                               │                               │                             │
│   [IoMT Telemetry Request]    │                               │                             │
│               │               │                               │                             │
│               ▼               │                               │                             │
│     [Zero Trust Policy Engine]│                               │                             │
│        (Phase 2 Baseline)     │                               │                             │
│               │               │                               │                             │
│               ▼               │                               │                             │
│    [AI Anomaly Scoring (OOF)] │                               │                             │
│         (Phase 3B Model)      │                               │                             │
│               │               │                               │                             │
│               ▼               │                               │                             │
│    [Dynamic Trust Engine]     │                               │                             │
│        (Phase 4 State)        │                               │                             │
│               │               │                               │                             │
│               ▼               │                               │                             │
│     Canonical Trust Event     │                               │                             │
│  (JSON Record + SHA-256 TxID) │                               │                             │
│               │               │                               │                             │
│               └───────────────┼───────────────►               │                             │
│                               │      Memory Pool (Mempool)    │                             │
│                               │               │               │                             │
│                               │               ▼               │                             │
│                               │     Merkle Tree Generation    │                             │
│                               │    (Transaction Batching)     │                             │
│                               │               │               │                             │
│                               │               ▼               │                             │
│                               │     Block Header Assembly     │                             │
│                               │ (PrevHash + MerkleRoot + PoW) │                             │
│                               │               │               │                             │
│                               │               ▼               │                             │
│                               │      Block Sealed & Stored    │                             │
│                               │               │               │                             │
│                               │               └───────────────┼───────────────►             │
│                               │                               │     Global Ledger Archive   │
│                               │                               │               │             │
│                               │                               │               ▼             │
│                               │                               │   Integrity Verification    │
│                               │                               │   & Tamper Detection Engine │
└───────────────────────────────┴───────────────────────────────┴─────────────────────────────┘
```

### 2.1 Multi-Tier Distribution Strategy
1. **Edge Tier (IoMT Devices `iotA1`–`iotB3`, Access Gateways):**
   - Transmits telemetry and receives Zero Trust authorization decisions.
   - Submits canonical audit event payloads to local memory pool.
   - Evaluates Merkle inclusion proofs (SPV / Simple Payment Verification style) to confirm event inclusion without storing the full ledger.
2. **Fog Tier (Local Fog Gateways `fogA`, `fogB`):**
   - Serves as the primary transaction validator and block builder.
   - Collects transactions into batches of size $B$, constructs the binary Merkle tree, calculates the Merkle root, and mines/seals the block.
   - Maintains a localized rolling ledger segment for rapid recovery and low-latency audit verification.
3. **Cloud Tier (Shared Cloud Server `cloud1`):**
   - Aggregates sealed blocks from all hospital tenants into an immutable master audit ledger.
   - Provides administrative query interfaces (`audit_device_history`, `verify_chain_integrity`).
   - Executes forensic tamper-detection and compliance reporting for regulatory oversight (HIPAA / GDPR).

---

## 3. Event Schema Mapped to Actual Phase 4 Fields

The blockchain transaction structure directly maps the 21 fields discovered in `results/phase4/phase4_trust_trace.csv` and integrates the authoritative UTC timestamp from `results/zerotrust/zerotrust_security_events.csv`.

### 3.1 Field-by-Field Mapping Table

| Phase 4 Field | Source File | Data Type | Canonical Ledger Field | Description & Semantics |
|---|---|---|---|---|
| `event_index` | `phase4_trust_trace.csv` | `int` | `event_index` | Monotonic sequential event counter ($0 \dots 24$). |
| `record_id` | `phase4_trust_trace.csv` | `str` (16-hex) | `record_id` | Unique request identifier preserved from Phase 3A/3B. |
| `timestamp_utc` | `zerotrust_security_events.csv` | `str` (ISO 8601) | `timestamp_utc` | Authoritative UTC timestamp of request generation. |
| `source_device` | `phase4_trust_trace.csv` | `str` | `device_id` | Originating IoMT identity (`iotA1`–`iotB3`). |
| `scenario` | `phase4_trust_trace.csv` | `str` | `scenario` | Evaluation scenario (e.g., `authorized_edge`, `cross_tenant`). |
| `p2_decision` | `phase4_trust_trace.csv` | `str` | `policy_decision` | Deterministic Phase 2 outcome (`ALLOW` / `DENY`). |
| `p2_reason` | `phase4_trust_trace.csv` | `str` | `policy_reason` | Deterministic reason code (e.g., `cross_tenant_denied`). |
| `jit_status` | `phase4_trust_trace.csv` | `str` | `jit_privilege` | Temporary privilege status (`Active` / `Inactive`). |
| `severity` | `phase4_trust_trace.csv` | `str` | `severity` | Security severity (`NONE`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `oof_score` | `phase4_trust_trace.csv` | `float` | `ai_anomaly_score` | Frozen Phase 3B Out-of-Fold anomaly probability $[0.0, 1.0]$. |
| `p_det` | `phase4_trust_trace.csv` | `float` | `penalty_det` | Deterministic penalty deducted from score. |
| `p_ai` | `phase4_trust_trace.csv` | `float` | `penalty_ai` | Auxiliary AI penalty deducted from score ($\le 15.0$). |
| `p_total` | `phase4_trust_trace.csv` | `float` | `penalty_total` | Total penalty ($P_{\text{det}} + P_{\text{ai}}$). |
| `rec` | `phase4_trust_trace.csv` | `float` | `recovery_gain` | Recovery increment awarded ($0.0$ or $2.0$). |
| `trust_before` | `phase4_trust_trace.csv` | `float` | `trust_before` | Pre-evaluation continuous score $[0.0, 100.0]$. |
| `trust_after` | `phase4_trust_trace.csv` | `float` | `trust_after` | Post-evaluation continuous score $[0.0, 100.0]$. |
| `state_before` | `phase4_trust_trace.csv` | `str` | `state_before` | Pre-evaluation dynamic state (`TRUSTED`, `RESTRICTED`, `REVOKED`). |
| `state_after` | `phase4_trust_trace.csv` | `str` | `state_after` | Post-evaluation dynamic state (`TRUSTED`, `RESTRICTED`, `REVOKED`). |
| `mapped_phase2_state` | `phase4_trust_trace.csv` | `str` | `mapped_state` | Mapped Phase 2 discrete state (`TRUSTED`, `SUSPICIOUS`, `REVOKED`). |
| `n_viol_before` | `phase4_trust_trace.csv` | `int` | `violations_before` | Pre-event consecutive policy violation counter. |
| `n_viol_after` | `phase4_trust_trace.csv` | `int` | `violations_after` | Post-event consecutive policy violation counter. |
| `action_taken` | `phase4_trust_trace.csv` | `str` | `action_taken` | Final policy enforcement action applied to the request. |

### 3.2 Canonical Transaction JSON Structure
```json
{
  "tx_id": "8f3b4c1e7a902d561234abcd5678ef0192837465aabbccddeeff001122334455",
  "event_index": 18,
  "record_id": "6c905147705120e0",
  "timestamp_utc": "2026-09-23T06:59:34.629112+00:00",
  "device_id": "iotA1",
  "scenario": "cross_tenant",
  "policy_decision": "DENY",
  "policy_reason": "cross_tenant_denied",
  "jit_privilege": "Inactive",
  "severity": "CRITICAL",
  "ai_anomaly_score": 0.227,
  "penalty_det": 50.0,
  "penalty_ai": 0.0,
  "penalty_total": 50.0,
  "recovery_gain": 0.0,
  "trust_before": 100.0,
  "trust_after": 50.0,
  "state_before": "TRUSTED",
  "state_after": "RESTRICTED",
  "mapped_state": "SUSPICIOUS",
  "violations_before": 0,
  "violations_after": 1,
  "action_taken": "DENY (cross_tenant_denied)"
}
```
**Canonical Transaction Hashing Rule:**
$\text{tx\_id} = \text{SHA256}(\text{canonical\_json}(\text{payload}))$, where `canonical_json` serializes the payload dictionary with sorted keys, no trailing whitespace, UTF-8 encoding, and deterministic numeric formatting.

---

## 4. Cryptographic Block & Hashing Design

### 4.1 Block Header Specification
Every block consists of a 6-tuple header:
1. `index` (`int`): Monotonic block height ($0, 1, 2, \dots$). Genesis block is index $0$.
2. `previous_hash` (`str`): 64-character hex string representing the SHA-256 hash of the immediate predecessor block header. For Genesis block, `previous_hash` is $64$ zeros (`"0" * 64`).
3. `merkle_root` (`str`): 64-character hex string representing the Merkle root of all transactions sealed in the block body. For Genesis block with no transactions, `merkle_root` is $\text{SHA256}(\text{""})$.
4. `timestamp` (`float` or `str`): UNIX timestamp or UTC ISO string indicating block formation time.
5. `difficulty` (`int`): Number of leading hex zeros required in the block hash (default $D=0$ for lightweight Zero-Trust audit sealing; configurable $D \ge 1$ for Proof-of-Work ablation).
6. `nonce` (`int`): Integer counter adjusted during block sealing until $\text{SHA256}(\text{header}) < 16^{(64 - \text{difficulty})}$.

### 4.2 Merkle Tree Construction
To ensure logarithmic ($O(\log N)$) verification and prevent transaction reordering:
1. Collect ordered transactions $[T_0, T_1, \dots, T_{k-1}]$ where $k$ is the batch size.
2. Compute transaction leaf hashes: $H_i = \text{SHA256}(\text{tx\_id}_i)$.
3. If the number of leaves is odd, duplicate the last leaf to maintain a complete binary tree.
4. Recursively pair adjacent hashes: $H_{\text{parent}} = \text{SHA256}(H_{\text{left}} \parallel H_{\text{right}})$.
5. Terminate when a single 32-byte root hash ($H_{\text{root}}$) is produced.

```text
                  [ Merkle Root ]
                         │
            ┌────────────┴────────────┐
         [ H_01 ]                  [ H_23 ]
            │                         │
      ┌─────┴─────┐             ┌─────┴─────┐
   [ H_0 ]     [ H_1 ]       [ H_2 ]     [ H_3 ]
      │           │             │           │
   [ Tx_0 ]    [ Tx_1 ]      [ Tx_2 ]    [ Tx_3 ]
```

### 4.3 Deterministic Block Serialization
To prevent serialization divergence across different platforms (Windows/Linux) or Python runtimes:
```python
header_dict = {
    "index": self.index,
    "previous_hash": self.previous_hash,
    "merkle_root": self.merkle_root,
    "timestamp": self.timestamp,
    "difficulty": self.difficulty,
    "nonce": self.nonce,
}
header_bytes = json.dumps(header_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
block_hash = hashlib.sha256(header_bytes).hexdigest()
```

---

## 5. Verification & Tamper-Detection Strategy

The verification engine provides a multi-layer defense against malicious modifications:

### 5.1 Verification Hierarchy
1. **Transaction Integrity Check:**
   - Recompute $\text{SHA256}(\text{canonical\_json}(\text{payload}))$ for each transaction and verify equality with `tx_id`.
   - *Threat Mitigated:* Mutation of trust scores, device IDs, or policy decisions.
2. **Merkle Root Integrity Check:**
   - Reconstruct the Merkle tree from all transaction leaf hashes and compare computed root against `block.header.merkle_root`.
   - *Threat Mitigated:* Deletion, reordering, or injection of transactions within a block.
3. **Block Header Integrity Check:**
   - Recompute $\text{SHA256}(\text{canonical\_header})$ and verify equality with stored `block_hash`.
   - Verify that `block_hash` satisfies the configured `difficulty` target.
   - *Threat Mitigated:* Alteration of block timestamp, index, or Merkle root.
4. **Chain Continuity Check:**
   - For every block $i \ge 1$, verify `block[i].previous_hash == block[i-1].block_hash`.
   - For Genesis block ($i = 0$), verify `block[0].previous_hash == "0" * 64`.
   - Verify strictly monotonic block indices ($i = 0, 1, 2, \dots$).
   - *Threat Mitigated:* Block insertion, block deletion, or blockchain fork attacks.

### 5.2 Forensic Tamper Pinpointing
The verification engine does not merely return boolean pass/fail; it returns a structured diagnostic report identifying:
- Exact block height where tampering occurred (`tampered_block_index`).
- Exact transaction identifier compromised (`tampered_tx_id`).
- Discrepancy category: `TX_PAYLOAD_TAMPERED`, `MERKLE_ROOT_MISMATCH`, `HEADER_HASH_MISMATCH`, `PREVIOUS_HASH_DISCONTINUITY`, `INDEX_GAP`.
- Expected hash vs. Observed hash.

---

## 6. Proposed Module Interfaces & Responsibilities

### 6.1 `src/blockchain/merkle.py`
- **Class:** `MerkleTree`
- **Methods:**
  - `__init__(leaves: list[str])`: Initializes tree with pre-hashed or unhashed leaves.
  - `get_root() -> str`: Returns 64-character hex Merkle root.
  - `get_proof(index: int) -> list[dict]`: Generates audit path (sibling hashes and directions) for SPV verification.
  - `verify_proof(leaf: str, proof: list[dict], root: str) -> bool`: Validates inclusion proof.

### 6.2 `src/blockchain/transaction.py`
- **Class:** `TrustTransaction`
- **Attributes:** Mapped Phase 4 fields + `tx_id`.
- **Methods:**
  - `from_trace_event(trace_row: dict, event_row: dict) -> "TrustTransaction"`: Factory creating canonical transaction from Phase 4 + Phase 2 rows.
  - `to_dict() -> dict`: Returns deterministic dictionary representation.
  - `compute_hash() -> str`: Computes canonical SHA-256 hash.
  - `verify_signature() -> bool`: Optional cryptographic signature verification placeholder.

### 6.3 `src/blockchain/block.py`
- **Class:** `BlockHeader`, `Block`
- **Methods:**
  - `compute_hash() -> str`: Computes block header SHA-256.
  - `seal(difficulty: int = 0) -> str`: Solves PoW or seals header instantly ($D=0$).
  - `to_dict() -> dict`: Serializes complete block including header and transactions.
  - `from_dict(d: dict) -> "Block"`: Deserializes stored block JSON.

### 6.4 `src/blockchain/ledger.py`
- **Class:** `BlockchainLedger`
- **Methods:**
  - `create_genesis_block() -> Block`: Initializes chain with hardcoded Genesis block.
  - `add_transaction(tx: TrustTransaction) -> None`: Appends transaction to mempool.
  - `seal_block(difficulty: int = 0) -> Block`: Batches mempool into a new block, computes Merkle root, links previous hash, and appends to chain.
  - `export_ledger(output_path: Path) -> None`: Exports entire ledger to JSON/JSONL format.
  - `load_ledger(input_path: Path) -> None`: Imports ledger from disk.
  - `get_device_history(device_id: str) -> list[TrustTransaction]`: Filters complete chronological event history for a specific IoMT device.

### 6.5 `src/blockchain/verifier.py`
- **Class:** `ChainVerifier`
- **Methods:**
  - `verify_chain(ledger: BlockchainLedger) -> tuple[bool, list[dict]]`: Validates the full chain and returns comprehensive diagnostic records.
  - `simulate_tamper(ledger: BlockchainLedger, tamper_type: str, block_idx: int, **kwargs) -> BlockchainLedger`: Creates a deep copy of ledger with simulated tamper injection for adversarial testing.

---

## 7. Proposed File and Directory Structure

```text
Cloud_Edge_Fog_AI_Zerotrust_Arch_Phase4_Frozen/
├── config/
│   ├── ai_feature_pipeline.yaml           [FROZEN - DO NOT MODIFY]
│   ├── ai_model_config.yaml               [FROZEN - DO NOT MODIFY]
│   ├── network_config.yaml                [FROZEN - DO NOT MODIFY]
│   ├── zero_trust_policy.yaml             [FROZEN - DO NOT MODIFY]
│   └── blockchain_config.yaml             [PHASE 5 - NEW CONFIGURATION]
├── experiments/
│   ├── run_mininet_phase1b.py             [FROZEN - DO NOT MODIFY]
│   ├── run_phase1.py                      [FROZEN - DO NOT MODIFY]
│   ├── run_phase3a_pipeline.py            [FROZEN - DO NOT MODIFY]
│   ├── run_phase3b_model.py               [FROZEN - DO NOT MODIFY]
│   ├── run_phase4_trust_replay.py         [FROZEN - DO NOT MODIFY]
│   ├── run_zerotrust_phase2.py            [FROZEN - DO NOT MODIFY]
│   └── run_phase5_blockchain.py           [PHASE 5 - NEW EXPERIMENT RUNNER]
├── plots/
│   ├── ...                                [FROZEN Phase 1-4 Plots]
│   └── phase5/                            [PHASE 5 - NEW PLOT DIRECTORY]
│       ├── blockchain_batch_latency.png   [PHASE 5 - EXPERIMENT PLOT]
│       └── blockchain_tamper_matrix.png   [PHASE 5 - EXPERIMENT PLOT]
├── results/
│   ├── ai/                                [FROZEN Phase 3 Results]
│   ├── fallback/                          [FROZEN Phase 1 Results]
│   ├── mininet/                           [FROZEN Phase 1 Results]
│   ├── phase4/                            [FROZEN Phase 4 Results]
│   ├── zerotrust/                         [FROZEN Phase 2 Results]
│   └── phase5/                            [PHASE 5 - NEW RESULTS DIRECTORY]
│       ├── phase5_blockchain_ledger.json  [PHASE 5 - SEALED BLOCKS & TXS]
│       ├── phase5_audit_verification.csv  [PHASE 5 - VERIFICATION LOGS]
│       ├── phase5_ablation_metrics.csv    [PHASE 5 - BATCH SIZE & LATENCY]
│       └── phase5_manifest.json           [PHASE 5 - SHA-256 PROVENANCE]
├── src/
│   ├── ai/                                [FROZEN Phase 3 Source]
│   ├── devices/                           [FROZEN Phase 1 Source]
│   ├── experiments/                       [FROZEN Phase 1 Source]
│   ├── topology/                          [FROZEN Phase 1 Source]
│   ├── traffic/                           [FROZEN Phase 1 Source]
│   ├── utils/                             [FROZEN Phase 1 Source]
│   ├── zerotrust/                         [FROZEN Phase 2 & 4 Source]
│   └── blockchain/                        [PHASE 5 - NEW SOURCE PACKAGE]
│       ├── __init__.py                    [PHASE 5 - PACKAGE INIT]
│       ├── block.py                       [PHASE 5 - BLOCK & HEADER MODELS]
│       ├── ledger.py                      [PHASE 5 - CHAIN & MEMPOOL ENGINE]
│       ├── merkle.py                      [PHASE 5 - MERKLE TREE LOGIC]
│       ├── transaction.py                 [PHASE 5 - EVENT TRANSFORMATION]
│       └── verifier.py                    [PHASE 5 - TAMPER AUDIT ENGINE]
├── tests/
│   ├── ...                                [FROZEN 45 Baseline Tests]
│   └── test_phase5_blockchain.py          [PHASE 5 - NEW UNIT & INTEGRATION TESTS]
├── PHASE1_RESULTS.md                      [FROZEN - DO NOT MODIFY]
├── PHASE5_BLOCKCHAIN_SPEC.md              [PHASE 5 - SPECIFICATION DOCUMENT]
├── PROJECT_STATUS.md                      [ALLOWED TO UPDATE STATUS]
├── README.md                              [ALLOWED TO UPDATE DOCUMENTATION]
└── requirements.txt                       [FROZEN / UNMODIFIED]
```

---

## 8. Experiment Plan & Test Cases

### 8.1 Experiment Plan
1. **Experiment 5A: Full Trace Blockchain Ingestion & Sealing**
   - Ingest all 25 chronological events from `results/phase4/phase4_trust_trace.csv` paired with `results/zerotrust/zerotrust_security_events.csv`.
   - Batch events into blocks using default batch size $B=5$ (yielding 1 Genesis block + 5 sealed transaction blocks).
   - Compute and record Merkle root, block hash, sealing latency, and export complete ledger to `results/phase5/phase5_blockchain_ledger.json`.
2. **Experiment 5B: Adversarial Tamper Injection & Detection Evaluation**
   - Inject 4 synthetic attack scenarios into a cloned ledger:
     - Scenario 1: Alter `trust_after` in Block 2, Tx 1 (e.g., from 0.0 to 100.0).
     - Scenario 2: Delete Tx 3 from Block 3.
     - Scenario 3: Modify timestamp in Block 4 header.
     - Scenario 4: Truncate / delete Block 5 from the chain.
   - Run `ChainVerifier` across all scenarios and verify 100% tamper detection and exact anomaly pinpointing.
   - Record results in `results/phase5/phase5_audit_verification.csv`.
3. **Experiment 5C: Batch Size & Proof Difficulty Ablation**
   - Evaluate batch sizes $B \in \{1, 5, 10, 25\}$.
   - Evaluate proof difficulty $D \in \{0, 1, 2, 3\}$.
   - Measure:
     - Block sealing latency (ms).
     - Merkle root computation time ($\mu\text{s}$).
     - Total ledger byte size (KB).
     - Verification throughput (blocks/sec).
   - Output summary table to `results/phase5/phase5_ablation_metrics.csv` and generate plots in `plots/phase5/`.

### 8.2 Test Suite Specification (`tests/test_phase5_blockchain.py`)
Phase 5 introduces a minimum of 18 dedicated unit and integration tests:
1. `test_01_genesis_block_creation`: Validates Genesis block height ($0$), `previous_hash` ($64$ zeros), and static initialization.
2. `test_02_transaction_canonical_serialization`: Confirms bitwise identical `tx_id` regardless of dictionary key ordering.
3. `test_03_transaction_mapping_fidelity`: Verifies all 21 Phase 4 fields and UTC timestamp correctly propagate into transaction payload.
4. `test_04_merkle_tree_single_leaf`: Verifies Merkle root of single transaction matches double hash of leaf.
5. `test_05_merkle_tree_odd_leaf_duplication`: Confirms standard RFC 6962 / Bitcoin style duplication of odd leaves.
6. `test_06_merkle_proof_verification`: Generates audit path for leaf and validates positive inclusion proof.
7. `test_07_merkle_proof_rejection_on_tamper`: Confirms modified leaf hash fails inclusion proof against valid root.
8. `test_08_block_hash_reproducibility`: Ensures block hash is strictly reproducible from identical header contents.
9. `test_09_blockchain_append_block`: Verifies block height increments and `previous_hash` points to prior block.
10. `test_10_ledger_ingest_all_25_events`: Validates complete 25-event Phase 4 trace processes into ledger without errors.
11. `test_11_chain_verification_valid_ledger`: Confirms untampered ledger returns `is_valid == True` and zero errors.
12. `test_12_detect_tampered_transaction_payload`: Injects payload mutation; verifier catches `TX_PAYLOAD_TAMPERED` and identifies exact block/tx.
13. `test_13_detect_merkle_root_mutation`: Modifies Merkle root; verifier catches `MERKLE_ROOT_MISMATCH`.
14. `test_14_detect_block_deletion`: Removes an intermediate block; verifier flags `PREVIOUS_HASH_DISCONTINUITY`.
15. `test_15_detect_block_insertion`: Inserts an extra block; verifier flags index gap or broken hash pointer.
16. `test_16_spv_device_history_audit`: Verifies extraction of complete audit history for `iotA1` matching Phase 4 trace.
17. `test_17_ledger_export_and_load_roundtrip`: Verifies bitwise round-trip persistence through JSON export and import.
18. `test_18_zero_phase1_4_artifact_contamination`: Verifies all frozen artifact SHA-256 hashes remain strictly unchanged.

---

## 9. Expected Output Files & Acceptance Criteria

### 9.1 Expected Output Files
1. `src/blockchain/__init__.py`
2. `src/blockchain/merkle.py`
3. `src/blockchain/transaction.py`
4. `src/blockchain/block.py`
5. `src/blockchain/ledger.py`
6. `src/blockchain/verifier.py`
7. `config/blockchain_config.yaml`
8. `experiments/run_phase5_blockchain.py`
9. `tests/test_phase5_blockchain.py`
10. `results/phase5/phase5_blockchain_ledger.json`
11. `results/phase5/phase5_audit_verification.csv`
12. `results/phase5/phase5_ablation_metrics.csv`
13. `results/phase5/phase5_manifest.json`
14. `plots/phase5/blockchain_batch_latency.png`
15. `plots/phase5/blockchain_tamper_matrix.png`

### 9.2 Acceptance Criteria
- **Test Suite Pass Rate:** All 45 existing Phase 1–4 tests pass with zero regressions, PLUS all 18 new Phase 5 tests pass ($63/63$ total passing tests).
- **Audit Completeness:** All 25 Phase 4 security and dynamic trust events are sealed in the ledger with verified Merkle roots and valid SHA-256 headers.
- **Tamper Detection Accuracy:** 100% detection rate on transaction payload mutations, transaction deletions, header tampering, and block removals.
- **Zero Phase 1–4 Contamination:** SHA-256 hashes of all protected files remain identical to baseline:
  - `src/zerotrust/dynamic_trust.py`: `5da36f2ca8d5a997d387a3ef325e3b0ce18ea38bcb45508d5c0e0ed909e8f519`
  - `results/zerotrust/zerotrust_security_events.csv`: `be661040b7eb0aba74a098195075c96af11d7fbc1319882a9b7fd7119ed5238b`
  - `results/ai/phase3a_iomt_anomaly_dataset.csv`: `284b1b5933c86f0fffd5a912a4ee3c2f019585b441c4b67097e04824d949cdd4`
  - `results/ai/phase3b_predictions.csv`: `f2fb282a417d3dbc53c31dde9260961fd4b6c3a7d425d55385023ebfb83a81e6`
  - `results/phase4/phase4_trust_trace.csv`: `c214728a41f7dacad9df105128b0a3ea686cf8be76646727fd12381c5c6e428d`
  - `results/phase4/phase4_ablation_metrics.csv`: `de5b7fbc0a16571f7dede132be2865f5c58c35bc3de01cbe74b112716474a809`
  - `tests/test_phase4_dynamic_trust.py`: `16894519e68dc5faf3da80779afb7f8f43bb4393ed3d484a4266d8a57cf8f581`
