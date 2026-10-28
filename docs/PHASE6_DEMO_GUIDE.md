# MedTrustEdge Phase 6 — Live Demonstration and Presentation Guide
## Interactive Walkthrough: Security Hardening, Cryptographic Checkpoints, and 10-Gate Validation

---

## 1. Demonstration Overview

This guide provides a structured, live demonstration script for reviewing and evaluating **MedTrustEdge Phase 6**. It allows evaluators, researchers, and stakeholders to walk through the system's cryptographic capabilities in under 10 minutes.

### Prerequisites
- Operating System: Windows, Linux, or macOS.
- Python 3.10+ (tested on Python 3.13 64-bit).
- Dependencies installed: `pip install -r requirements.txt`.
- Working Directory: Repository root.

---

## 2. Step-by-Step Live Walkthrough

### Step 1: Verify Baseline Environment and Golden Hashes (1 Minute)
Demonstrate that the repository is on a clean branch and all frozen historical artifacts from Phases 1–4 are cryptographically intact.

```powershell
# 1.1 Verify git branch and commit status
git status

# 1.2 Run baseline SHA-256 integrity check
python -c "
import hashlib
from pathlib import Path
protected = {
    'src/zerotrust/dynamic_trust.py': '5da36f2ca8d5a997d387a3ef325e3b0ce18ea38bcb45508d5c0e0ed909e8f519',
    'results/zerotrust/zerotrust_security_events.csv': 'be661040b7eb0aba74a098195075c96af11d7fbc1319882a9b7fd7119ed5238b',
    'results/ai/phase3a_iomt_anomaly_dataset.csv': '284b1b5933c86f0fffd5a912a4ee3c2f019585b441c4b67097e04824d949cdd4',
    'results/ai/phase3b_predictions.csv': 'f2fb282a417d3dbc53c31dde9260961fd4b6c3a7d425d55385023ebfb83a81e6',
    'results/phase4/phase4_trust_trace.csv': 'c214728a41f7dacad9df105128b0a3ea686cf8be76646727fd12381c5c6e428d',
    'results/phase4/phase4_ablation_metrics.csv': 'de5b7fbc0a16571f7dede132be2865f5c58c35bc3de01cbe74b112716474a809',
    'tests/test_phase4_dynamic_trust.py': '16894519e68dc5faf3da80779afb7f8f43bb4393ed3d484a4266d8a57cf8f581',
}
print('Auditing 7 protected baseline artifacts...')
for path_str, exp_hash in protected.items():
    raw = Path(path_str).read_bytes()
    if path_str.endswith('.py'): raw = raw.replace(b'\r\n', b'\n')
    act = hashlib.sha256(raw).hexdigest()
    assert act == exp_hash, f'Mismatch in {path_str}'
    print(f'  [PASS] {path_str}: {act[:12]}...')
print('All 7 baseline hashes 100% verified!')
"
```

**Oral Talking Point:**
> *"Notice that all historical artifacts from Phases 1, 2, 3A, 3B, and 4 are strictly read-only and match their golden SHA-256 baselines bit-for-bit."*

---

### Step 2: Centralized Configuration and Fail-Fast Validation (1 Minute)
Demonstrate that the new centralized YAML configuration enforces strict boundaries.

```powershell
# 2.1 View the active configuration
Get-Content config/blockchain_config.yaml

# 2.2 Demonstrate fail-fast boundary enforcement
python -c "
from src.blockchain.config import load_blockchain_config, ConfigValidationError
try:
    load_blockchain_config(overrides={'ledger': {'batch_size': -5}})
    print('FAILED: Invalid config accepted!')
except ConfigValidationError as e:
    print('SUCCESS: Detected invalid config:', e)
"
```

**Oral Talking Point:**
> *"Phase 6 eliminates hardcoded magic numbers by centralizing operational parameters into a typed dataclass schema that immediately fails fast if an operator enters invalid parameters."*

---

### Step 3: Cryptographic Checkpoint Anchoring & Fork Attack Detection (2 Minutes)
Demonstrate how RFC 8032 Ed25519 digital signatures prevent whole-chain ledger rewrite attacks.

```powershell
python -c "
from src.blockchain import BlockchainLedger, EventAdapter, create_checkpoint, verify_ledger_against_checkpoint, generate_ed25519_keypair
from pathlib import Path
import copy

# 1. Build authentic ledger
adapter = EventAdapter()
events = adapter.adapt(Path('results/phase4/phase4_trust_trace.csv'), Path('results/zerotrust/zerotrust_security_events.csv'))
ledger = BlockchainLedger.build_from_events(events, batch_size=5)

# 2. Generate Ed25519 keypair and checkpoint authentic ledger tip
sk, vk = generate_ed25519_keypair()
checkpoint = create_checkpoint(ledger.latest_block, algorithm='ed25519', private_key_hex=sk, cumulative_event_count=ledger.total_event_count)
print('Authentic Checkpoint Created. Block Hash:', checkpoint.block_hash[:16])

# 3. Verify authentic ledger matches checkpoint
verify_ledger_against_checkpoint(ledger, checkpoint, public_key_hex=vk)
print('[PASS] Authentic ledger matches signed checkpoint.')

# 4. Simulate Fork Rewrite Attack: Adversary builds a forged chain from Genesis
forged_events = copy.deepcopy(events)
forged_events[0].payload['action'] = 'FORGED_ATTACK'
forged_events[0].event_hash = 'ffff' * 16
forged_ledger = BlockchainLedger.build_from_events(forged_events, batch_size=5)

# 5. Checkpoint catches the substitution!
try:
    verify_ledger_against_checkpoint(forged_ledger, checkpoint, public_key_hex=vk)
    print('FAILED: Forged chain accepted!')
except Exception as e:
    print('[DETECTED] Whole-chain substitution caught by checkpoint:', e)
"
```

**Oral Talking Point:**
> *"Here we simulate an attacker rewriting the entire blockchain from Genesis. While the forged chain might be internally valid, our external Ed25519 checkpoint immediately catches and rejects the substitution."*

---

### Step 4: Adversarial Tamper Detection Suite (2 Minutes)
Demonstrate the 8-attack adversarial evaluation suite.

```powershell
python -c "
from experiments.run_phase5_tamper_experiments import run_all_tamper_experiments
exps, summary = run_all_tamper_experiments(batch_size=5)
print(f'Total Attacks Simulated: {summary[\"evaluation_summary\"][\"total_attacks_simulated\"]}')
print(f'Total Attacks Detected: {summary[\"evaluation_summary\"][\"total_attacks_detected\"]}')
print(f'Detection Rate: {summary[\"evaluation_summary\"][\"detection_rate_percent\"]}%\n')
for e in exps:
    print(f'  [{e[\"experiment_code\"]}] {e[\"attack_name\"]} -> {e[\"detection_status\"]} ({e[\"primary_error_category\"]})')
"
```

**Oral Talking Point:**
> *"The forensic engine evaluates eight distinct attack vectors—payload tampering, hash corruption, header manipulation, broken previous-hash pointers, event reordering, block swapping, event deletion, and block deletion. All 8 are detected with 100% precision."*

---

### Step 5: Execute the 10-Gate Validation Runner (2 Minutes)
Run the full automated Phase 6 validation runner and inspect the immutable run manifest.

```powershell
python experiments/run_phase6_final_validation.py
```

Inspect the output directory:
```powershell
Get-ChildItem results/phase6/run_* | Select-Object -First 1
```

**Oral Talking Point:**
> *"The 10-gate validation runner executes our complete verification pipeline in under 1.5 seconds, outputting an isolated timestamped directory containing a machine-readable run manifest and a comprehensive Markdown report."*

---

### Step 6: Execute the Full 115-Test Suite (2 Minutes)
Demonstrate full system stability across all six project phases.

```powershell
python -m unittest discover -s tests -v
```

**Oral Talking Point:**
> *"All 115 unit and integration tests across Phases 1 through 6 pass cleanly with zero failures and zero skipped tests."*

---

## 3. Frequently Asked Questions & Reviewer Responses

### Q1: Why not use a standard relational database with hash triggers?
> **Answer:** *A database with hash triggers relies on DBMS-internal trust and mutable tables. A blockchain audit ledger binds event payloads into binary Merkle trees and sequential SHA-256 block hash pointers, creating a mathematically immutable directed acyclic structure where individual records can be proven using compact logarithmic inclusion proofs without exposing the entire dataset.*

### Q2: Is this a distributed blockchain like Bitcoin or Ethereum?
> **Answer:** *No. MedTrustEdge is intentionally scoped as a high-throughput, single-node hash-linked audit ledger tailored for healthcare Edge/Fog gateways. By eliminating proof-of-work mining and distributed gossip protocols, we achieve over 8,500 events per second verification throughput and sub-millisecond latencies, while external cryptographic checkpoints (RFC 8032 Ed25519) provide trust anchoring.*

### Q3: What happens if an IoMT device's private signing key is stolen?
> **Answer:** *Our Phase 4 dynamic trust engine continuously evaluates anomaly scores from Phase 3B and policy decisions from Phase 2. If an adversary attempts unauthorized service calls or anomalous traffic patterns, dynamic trust scores degrade rapidly, triggering immediate network quarantine via iptables before significant harm can occur.*
