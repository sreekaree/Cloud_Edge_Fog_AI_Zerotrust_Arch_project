"""MedTrustEdge Phase 6 — Cryptographic Ledger Checkpoint Subsystem.

Provides independent cryptographic checkpointing for the local blockchain ledger.
Implements dual-mode authentication:
1. Ed25519 Asymmetric Digital Signatures (RFC 8032) for public verification & non-repudiation.
2. HMAC-SHA256 Symmetric MACs for pre-shared secret node-to-node authentication.

Detects complete ledger rewrite (fork substitution from Genesis) by binding the ledger tip
(block index, block hash, Merkle root, cumulative event count) to an externally pinned
cryptographic identity.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Optional, Union
import uuid

# =============================================================================
# Custom Exception Hierarchy
# =============================================================================

class CheckpointError(Exception):
    """Base exception for cryptographic checkpoint failures."""
    pass


class CheckpointSignatureError(CheckpointError):
    """Raised when checkpoint signature or MAC verification fails."""
    pass


class CheckpointKeyError(CheckpointError):
    """Raised when an invalid, missing, or malformed cryptographic key is supplied."""
    pass


class CheckpointValidationError(CheckpointError):
    """Raised when checkpoint payload structure, schema, or ledger alignment fails."""
    pass


# =============================================================================
# RFC 8032 Pure-Python Ed25519 Implementation (Standard Library Native)
# =============================================================================

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(z: int) -> int:
    return pow(z, _P - 2, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_By = 4 * _inv(5) % _P
_Bx = _xrecover(_By)
_B = (_Bx, _By)


def _edwards_add(P: tuple[int, int], Q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2) % _P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2) % _P
    return (x3, y3)


def _scalarmult(P: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _point_compress(P: tuple[int, int]) -> bytes:
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _point_decompress(s: bytes) -> tuple[int, int]:
    if len(s) != 32:
        raise ValueError("Invalid compressed point length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (s[31] >> 7):
        x = _P - x
    return (x, y)


def _ed25519_sk_to_pk(sk: bytes) -> bytes:
    if len(sk) != 32:
        raise CheckpointKeyError(f"Ed25519 private key must be exactly 32 bytes, got {len(sk)}")
    h = hashlib.sha512(sk).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    A = _scalarmult(_B, a)
    return _point_compress(A)


def _ed25519_sign(sk: bytes, m: bytes) -> bytes:
    if len(sk) != 32:
        raise CheckpointKeyError(f"Ed25519 private key must be exactly 32 bytes, got {len(sk)}")
    h = hashlib.sha512(sk).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    A = _point_compress(_scalarmult(_B, a))
    prefix = h[32:]
    r = int.from_bytes(hashlib.sha512(prefix + m).digest(), "little") % _Q
    R = _scalarmult(_B, r)
    Rs = _point_compress(R)
    k = int.from_bytes(hashlib.sha512(Rs + A + m).digest(), "little") % _Q
    S = (r + k * a) % _Q
    return Rs + S.to_bytes(32, "little")


def _ed25519_verify(pk: bytes, m: bytes, sig: bytes) -> bool:
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        R = _point_decompress(sig[:32])
        A = _point_decompress(pk)
    except Exception:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _Q:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pk + m).digest(), "little") % _Q
    return _scalarmult(_B, S) == _edwards_add(R, _scalarmult(A, k))


# =============================================================================
# Ledger Checkpoint Data Structure
# =============================================================================

@dataclass
class LedgerCheckpoint:
    """Represents a signed cryptographic anchor representing the ledger state."""
    checkpoint_id: str
    timestamp_utc: str
    block_index: int
    block_hash: str
    merkle_root: str
    total_event_count: int
    key_id: str
    algorithm: str
    signature: str

    def to_canonical_payload(self) -> bytes:
        """Serializes checkpoint payload attributes (excluding signature) deterministically."""
        payload_dict = {
            "algorithm": self.algorithm,
            "block_hash": self.block_hash,
            "block_index": self.block_index,
            "checkpoint_id": self.checkpoint_id,
            "key_id": self.key_id,
            "merkle_root": self.merkle_root,
            "timestamp_utc": self.timestamp_utc,
            "total_event_count": self.total_event_count,
        }
        json_str = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return json_str.encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        """Serializes full checkpoint including signature to a dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serializes full checkpoint to JSON."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, separators=(",", ":") if indent is None else None)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LedgerCheckpoint:
        """Constructs LedgerCheckpoint from a dictionary with strict validation."""
        required = [
            "checkpoint_id",
            "timestamp_utc",
            "block_index",
            "block_hash",
            "merkle_root",
            "total_event_count",
            "key_id",
            "algorithm",
            "signature",
        ]
        for field_name in required:
            if field_name not in data:
                raise CheckpointValidationError(f"Missing required checkpoint field: {field_name}")

        cp = cls(
            checkpoint_id=str(data["checkpoint_id"]),
            timestamp_utc=str(data["timestamp_utc"]),
            block_index=int(data["block_index"]),
            block_hash=str(data["block_hash"]),
            merkle_root=str(data["merkle_root"]),
            total_event_count=int(data["total_event_count"]),
            key_id=str(data["key_id"]),
            algorithm=str(data["algorithm"]),
            signature=str(data["signature"]),
        )
        cp.validate_schema()
        return cp

    @classmethod
    def from_json(cls, json_str: str) -> LedgerCheckpoint:
        """Constructs LedgerCheckpoint from a JSON string."""
        try:
            data = json.loads(json_str)
        except Exception as exc:
            raise CheckpointValidationError(f"Invalid JSON string for checkpoint: {exc}") from exc
        if not isinstance(data, dict):
            raise CheckpointValidationError("Checkpoint JSON must decode to a dictionary")
        return cls.from_dict(data)

    def validate_schema(self) -> None:
        """Validates internal field types and cryptographic boundaries."""
        if self.block_index < 0:
            raise CheckpointValidationError(f"block_index cannot be negative: {self.block_index}")
        if self.total_event_count < 0:
            raise CheckpointValidationError(f"total_event_count cannot be negative: {self.total_event_count}")
        if len(self.block_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in self.block_hash):
            raise CheckpointValidationError(f"block_hash must be 64-char hex, got: {self.block_hash}")
        if len(self.merkle_root) != 64 or not all(c in "0123456789abcdefABCDEF" for c in self.merkle_root):
            raise CheckpointValidationError(f"merkle_root must be 64-char hex, got: {self.merkle_root}")
        if self.algorithm not in {"Ed25519", "HMAC-SHA256"}:
            raise CheckpointValidationError(f"Unsupported algorithm: {self.algorithm}")
        if not self.signature or not isinstance(self.signature, str):
            raise CheckpointValidationError("Checkpoint signature must be a non-empty string")


# =============================================================================
# Key Management and Cryptographic Helpers
# =============================================================================

def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generates an RFC 8032 Ed25519 private key (32 bytes) and public key (32 bytes)."""
    sk = os.urandom(32)
    pk = _ed25519_sk_to_pk(sk)
    return sk, pk


def generate_hmac_key(length_bytes: int = 32) -> str:
    """Generates a cryptographically secure random hexadecimal secret for HMAC-SHA256."""
    return os.urandom(length_bytes).hex()


def resolve_key(key: Union[str, bytes, None], env_var_name: Optional[str] = None) -> bytes:
    """Resolves raw key bytes from argument or environment variable."""
    if key is not None:
        if isinstance(key, bytes):
            return key
        if isinstance(key, str):
            try:
                # Try hex decoding if 64 chars
                if len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key):
                    return bytes.fromhex(key)
            except Exception:
                pass
            return key.encode("utf-8")

    if env_var_name:
        env_val = os.getenv(env_var_name)
        if env_val:
            try:
                if len(env_val) == 64 and all(c in "0123456789abcdefABCDEF" for c in env_val):
                    return bytes.fromhex(env_val)
            except Exception:
                pass
            return env_val.encode("utf-8")

    raise CheckpointKeyError("No cryptographic key provided or found in environment variable")


# =============================================================================
# Signing and Verification Engines
# =============================================================================

def sign_checkpoint_hmac(payload_bytes: bytes, secret_key: Union[str, bytes]) -> str:
    """Signs canonical payload bytes using HMAC-SHA256."""
    key_bytes = resolve_key(secret_key)
    if len(key_bytes) < 16:
        raise CheckpointKeyError("HMAC secret key must be at least 16 bytes for security")
    mac = hmac.new(key_bytes, payload_bytes, hashlib.sha256).hexdigest()
    return mac


def sign_checkpoint_ed25519(payload_bytes: bytes, private_key: Union[str, bytes]) -> str:
    """Signs canonical payload bytes using Ed25519 digital signature."""
    sk_bytes = resolve_key(private_key)
    if len(sk_bytes) != 32:
        raise CheckpointKeyError(f"Ed25519 signing key must be exactly 32 bytes, got {len(sk_bytes)}")
    sig_bytes = _ed25519_sign(sk_bytes, payload_bytes)
    return sig_bytes.hex()


def create_checkpoint(
    ledger: Any,
    key_id: str = "edge-gateway-alpha-01",
    algorithm: str = "Ed25519",
    key: Union[str, bytes, None] = None,
    checkpoint_id: Optional[str] = None,
    timestamp_utc: Optional[str] = None,
) -> LedgerCheckpoint:
    """Creates, signs, and returns an anchored LedgerCheckpoint from a live BlockchainLedger."""
    blocks_list = getattr(ledger, "blocks", getattr(ledger, "chain", None))
    if not blocks_list:
        raise CheckpointValidationError("Cannot create checkpoint from an empty ledger")

    tip_block = getattr(ledger, "latest_block", blocks_list[-1])
    tip_index = tip_block.header.index
    tip_hash = tip_block.header.block_hash
    tip_merkle = tip_block.header.merkle_root

    # Calculate cumulative event count
    if hasattr(ledger, "total_event_count"):
        cumulative_events = ledger.total_event_count
    else:
        cumulative_events = sum(len(b.events) for b in blocks_list)

    cid = checkpoint_id or uuid.uuid4().hex[:16]
    ts = timestamp_utc or datetime.now(timezone.utc).isoformat()

    cp = LedgerCheckpoint(
        checkpoint_id=cid,
        timestamp_utc=ts,
        block_index=tip_index,
        block_hash=tip_hash,
        merkle_root=tip_merkle,
        total_event_count=cumulative_events,
        key_id=key_id,
        algorithm=algorithm,
        signature="",
    )

    payload_bytes = cp.to_canonical_payload()

    if algorithm == "Ed25519":
        cp.signature = sign_checkpoint_ed25519(payload_bytes, key)
    elif algorithm == "HMAC-SHA256":
        cp.signature = sign_checkpoint_hmac(payload_bytes, key)
    else:
        raise CheckpointValidationError(f"Unsupported checkpoint algorithm: {algorithm}")

    return cp


def verify_checkpoint(
    checkpoint: LedgerCheckpoint,
    key: Union[str, bytes, None] = None,
    env_var_name: Optional[str] = None,
) -> bool:
    """Verifies the internal cryptographic authenticity of a LedgerCheckpoint.

    Raises CheckpointSignatureError or CheckpointKeyError if verification fails.
    """
    checkpoint.validate_schema()
    payload_bytes = checkpoint.to_canonical_payload()
    key_bytes = resolve_key(key, env_var_name)

    if checkpoint.algorithm == "HMAC-SHA256":
        expected_mac = sign_checkpoint_hmac(payload_bytes, key_bytes)
        if not hmac.compare_digest(checkpoint.signature.lower(), expected_mac.lower()):
            raise CheckpointSignatureError(
                f"HMAC checkpoint signature verification failed for checkpoint {checkpoint.checkpoint_id}"
            )
        return True

    elif checkpoint.algorithm == "Ed25519":
        if len(key_bytes) != 32:
            raise CheckpointKeyError(f"Ed25519 public key must be exactly 32 bytes, got {len(key_bytes)}")
        try:
            sig_bytes = bytes.fromhex(checkpoint.signature)
        except Exception as exc:
            raise CheckpointSignatureError(f"Invalid hex signature in checkpoint: {exc}") from exc
        valid = _ed25519_verify(key_bytes, payload_bytes, sig_bytes)
        if not valid:
            raise CheckpointSignatureError(
                f"Ed25519 digital signature verification failed for checkpoint {checkpoint.checkpoint_id}"
            )
        return True

    raise CheckpointValidationError(f"Unsupported algorithm: {checkpoint.algorithm}")


def verify_ledger_against_checkpoint(
    ledger: Any,
    checkpoint: LedgerCheckpoint,
    key: Union[str, bytes, None] = None,
    env_var_name: Optional[str] = None,
) -> tuple[bool, list[str]]:
    """Verifies that a BlockchainLedger matches the state anchored in a LedgerCheckpoint.

    Returns (is_valid, diagnostics_list).
    """
    diagnostics: list[str] = []

    # 1. Verify checkpoint cryptographic signature
    try:
        verify_checkpoint(checkpoint, key, env_var_name)
    except CheckpointError as exc:
        diagnostics.append(f"Checkpoint signature check failed: {exc}")
        return False, diagnostics

    # 2. Check if block index exists in ledger
    blocks_list = getattr(ledger, "blocks", getattr(ledger, "chain", []))
    if len(blocks_list) <= checkpoint.block_index:
        diagnostics.append(
            f"Ledger height ({len(blocks_list)}) is insufficient for checkpoint block index {checkpoint.block_index}"
        )
        return False, diagnostics

    target_block = blocks_list[checkpoint.block_index]

    # 3. Check block hash
    if target_block.header.block_hash.lower() != checkpoint.block_hash.lower():
        diagnostics.append(
            f"Block hash mismatch at index {checkpoint.block_index}: ledger '{target_block.header.block_hash}' vs checkpoint '{checkpoint.block_hash}'"
        )

    # 4. Check Merkle root
    if target_block.header.merkle_root.lower() != checkpoint.merkle_root.lower():
        diagnostics.append(
            f"Merkle root mismatch at index {checkpoint.block_index}: ledger '{target_block.header.merkle_root}' vs checkpoint '{checkpoint.merkle_root}'"
        )

    # 5. Check cumulative event count up to checkpoint index
    ledger_events_count = sum(len(b.events) for b in blocks_list[: checkpoint.block_index + 1])
    if ledger_events_count != checkpoint.total_event_count:
        diagnostics.append(
            f"Event count mismatch up to index {checkpoint.block_index}: ledger has {ledger_events_count} vs checkpoint {checkpoint.total_event_count}"
        )

    is_valid = len(diagnostics) == 0
    return is_valid, diagnostics
