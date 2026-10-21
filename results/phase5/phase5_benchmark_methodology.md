# MedTrustEdge Phase 5 — Performance Benchmarking & Ablation Methodology

This document details the benchmarking framework, statistical treatment, hardware profile, workload generation conventions, ablation studies, and theoretical analysis for the **Phase 5 Blockchain Ledger** of the MedTrustEdge project.

---

## 1. Benchmarking Environment & Hardware Profile

All benchmarks were conducted locally using the host execution environment:

- **Host Operating System:** Windows 11 (Build 10.0.26300)
- **CPU Architecture:** Intel64 Family 6 Model 186 Stepping 2 (GenuineIntel)
- **Python Runtime:** Python 3.13.2 (64-bit)
- **High-Resolution Clock:** `time.perf_counter()` (backed by Windows QueryPerformanceCounter, offering sub-microsecond precision)
- **Heap Memory Tracking:** Python Standard Library `tracemalloc` (tracking peak byte allocations directly attributed to the target operation)
- **Plotting Subsystem:** Matplotlib (Agg headless backend, 300 DPI publication quality)

---

## 2. Statistical Treatment & Repetition Framework

Single-shot measurements in dynamic runtimes like CPython suffer from JIT warmup artifacts, cold-import overhead, garbage collection jitter, and operating system page faults. To ensure scientific rigor and repeatability, the benchmarking harness applies the following protocol:

1. **Warmup Passes:**
   Every benchmarked operation executes 2 untimed warmup iterations prior to measurement. This pre-populates internal lookup caches, ensures module bytecode compilation, and primes memory pools.

2. **Multi-Iteration Repetitions:**
   - **Baseline real trace ($N=25$):** 30 timed iterations.
   - **Synthetic scaling workloads ($N \le 250$):** 20 timed iterations.
   - **Large synthetic workloads ($N \in \{500, 1000\}$):** 10 timed iterations.
   - **Batch size ablation sweeps ($N=100$):** 20 timed iterations.

3. **Metric Calculations:**
   - **Mean Execution Time ($\mu$):** $\mu = \frac{1}{R} \sum_{i=1}^R t_i$
   - **Sample Standard Deviation ($\sigma$):** $\sigma = \sqrt{\frac{1}{R-1} \sum_{i=1}^R (t_i - \mu)^2}$
   - **Extreme Values:** Minimum ($t_{\min}$) and Maximum ($t_{\max}$) recorded execution times.
   - **Throughput (Events / sec):** $\text{Throughput} = \frac{N}{\mu / 1000.0}$ where $N$ is the number of events processed and $\mu$ is in milliseconds.
   - **Peak Memory Usage:** Absolute peak heap memory in kilobytes allocated during the timed loop via `tracemalloc.get_traced_memory()`.

---

## 3. Workload Definitions & Data Generation

Two workload classes were benchmarked:

### A. Real Baseline Dataset ($N=25, B=5$)
- **Source Files:**
  - Preserved Phase 4 dynamic trust trace: `results/phase4/phase4_trust_trace.csv` (25 records, 21 fields)
  - Preserved Phase 2 Zero Trust security events: `results/zerotrust/zerotrust_security_events.csv`
- **Characteristics:**
  - Real project trace spanning 6 IoT devices (`iotA1`, `iotA2`, `iotA3`, `iotB1`, `iotB2`, `iotB3`)
  - Joined strictly on verified `record_id` (16-character SHA-256 slice)
  - Grouped into 6 blocks (1 Genesis block with 0 events + 5 transaction blocks with 5 events each)

### B. Deterministic Synthetic Generative Model ($N \in [25, 1000]$)
- To measure algorithmic scaling beyond the 25 frozen real events without mutating baseline data, a strictly deterministic synthetic generator was constructed in `experiments/run_phase5_performance_benchmarks.py`.
- **Determinism:**
  - Zero pseudo-random seed dependency.
  - All fields (timestamps, devices, decisions, trust scores, penalty multipliers, violation counts) are mathematical modular projections of the integer record index $i \in [0, N-1]$.
  - Timestamps progress monotonically by exactly 2.0 seconds per event: $T_i = T_{\text{base}} + i \times 2.0\text{s}$.
  - Record IDs are deterministic hexadecimal digests: `syn_{i:012x}`.
  - All synthetic records pass 100% of the validation constraints enforced by `TrustEvent` and `EventAdapter`.

---

## 4. Benchmarked Operations Across the Pipeline

Six distinct operations were evaluated:

1. **Event Adaptation (`event_adaptation`):**
   - Ingests raw record dictionaries (Phase 4 dynamic trust + Phase 2 authorization), joins on `record_id`, performs boundary validation across all 22 fields, sorts chronologically, and instantiates immutable `TrustEvent` instances.
2. **Ledger Construction (`ledger_construction`):**
   - Batches events into mempool queues, constructs Genesis Block 0, builds transaction blocks with batch size $B$, constructs per-block Merkle trees, computes SHA-256 block header hashes, and links cryptographic hash pointers (`previous_hash`).
3. **Merkle-Root Calculation (`merkle_root_calculation`):**
   - Isolates binary Merkle tree creation from event hashes, applying odd-node duplication and pairwise internal node hashing `SHA-256(left + right)`.
4. **Full-Chain Verification (`full_chain_verification`):**
   - Executes `ChainVerifier.verify_ledger()`. Evaluates Genesis parameters, sequential block indices, header SHA-256 digests, previous-block hash linkage, canonical JSON event payload hashes, chronological timestamp progression, Merkle tree root matches, and audit inclusion proof verification for every sealed event.
5. **Ledger Serialization & Deserialization (`ledger_serialization` & `ledger_deserialization`):**
   - Serializes the entire in-memory ledger structure into canonical formatted JSON strings and deserializes JSON strings back into live `BlockchainLedger` objects.
6. **Inclusion-Proof Verification Isolated (`inclusion_proofs_only`):**
   - Evaluates the generation of $O(\log_2 B)$ sibling proof paths and cryptographic verification against the block Merkle root for all events.

---

## 5. Ablation Studies

### Ablation 1: Batch Size Sensitivity Analysis ($B \in [1, 2, 5, 10, 25, 50]$ for $N=100$)
- **Objective:** Quantify the trade-off between block header overhead and Merkle tree depth.
- **Configurations Evaluated:**
  - $B=1$: 101 blocks (1 Genesis + 100 blocks). Maximum block header overhead; trivial single-leaf Merkle roots.
  - $B=2$: 51 blocks (1 Genesis + 50 blocks).
  - $B=5$: 21 blocks (1 Genesis + 20 blocks).
  - $B=10$: 11 blocks (1 Genesis + 10 blocks).
  - $B=25$: 5 blocks (1 Genesis + 4 blocks).
  - $B=50$: 3 blocks (1 Genesis + 2 blocks).
- **Key Findings:**
  - Moving from $B=1$ to $B=10$ reduces construction latency by **27.1%** (from 12.62 ms to 9.20 ms) due to 90 fewer block header serializations and hash computations.
  - Serialized JSON disk footprint decreases from **159.0 KB** ($B=1$) to **112.9 KB** ($B=10$) and **108.7 KB** ($B=50$), saving **31.6%** in storage overhead.
  - For $B \ge 10$, verification time stabilizes around ~35 ms because the reduction in block headers balances the logarithmic increase in Merkle inclusion proof depth ($\log_2 B$).

### Ablation 2: Verification Component Ablation (Inclusion Proofs vs. Structural Audit)
- **Objective:** Determine the computational distribution between structural ledger checks (headers, linkages, payload hashes, Merkle root recomputation) versus individual Merkle inclusion proofs.
- **Key Findings:**
  - Across all evaluated event counts, Merkle inclusion proof generation and verification account for **51.3% – 54.6%** of total verification runtime.
  - For the baseline real dataset ($N=25$):
    - Complete verification: **7.948 ms**
    - Structural & Merkle root verification (without inclusion proofs): **5.676 ms**
    - Inclusion proof verification isolated: **4.074 ms** (ratio: 51.3% of complete verification)
  - This indicates that in resource-constrained edge gateways, periodic full-chain validation can optionally verify Merkle roots and block linkages at high frequency (~4,400 events/sec), while deferring leaf-level inclusion proofs to on-demand dispute resolution.

---

## 6. Algorithmic Complexity vs. Empirical Scaling

| Operation | Theoretical Time Complexity | Empirical Behavior Observed | Bottleneck |
|---|---|---|---|
| **Event Adaptation** | $O(N)$ | Strictly linear ($R^2 > 0.999$); ~17,200 – 19,200 events/sec | ISO 8601 string parsing & dictionary key normalization |
| **Ledger Construction** | $O(N)$ with $O(N/B)$ headers | Strictly linear; ~11,200 – 11,500 events/sec | Canonical JSON header serialization & SHA-256 |
| **Merkle Root Calculation** | $O(B)$ per block $\to O(N)$ total | Ultra-fast; ~144,000 – 158,000 events/sec | In-memory string concatenation and SHA-256 |
| **Full Verification** | $O(N \log_2 B)$ | Linear in $N$ for fixed $B$; ~2,820 – 3,145 events/sec | Canonical serialization of event payloads & inclusion proof hashing |
| **Serialization (JSON)** | $O(N)$ | Linear; ~6,500 – 7,200 events/sec | CPython JSON string formatting and memory allocation |
| **Deserialization (JSON)** | $O(N)$ | Linear; ~17,800 – 22,200 events/sec | CPython native C-JSON decoder |

---

## 7. Security Boundary & Distributed Systems Disclaimer

> [!IMPORTANT]
> **Single-Node Cryptographic Benchmarks vs. Distributed Consensus:**
> The measurements reported herein evaluate the computational, cryptographic, and memory performance of the local Python implementation of the MedTrustEdge Phase 5 blockchain data structures.
>
> - **Included Scope:** Deterministic canonical JSON serialization, SHA-256 hashing, binary Merkle tree synthesis, inclusion proof path resolution, and sequential cryptographic pointer verification.
> - **Excluded Scope (Distributed Systems):** These benchmarks do **NOT** model peer-to-peer (P2P) network gossip latency, transport-layer packet serialization, Byzantine fault tolerant (BFT) consensus round-trips, raft leader election, disk I/O fsync stalls, or concurrent database locking contention.
> - In a production distributed healthcare cloud–fog–edge deployment, overall transaction throughput would be governed by network round-trip time (RTT) and consensus consensus finality rather than local SHA-256 computation.
