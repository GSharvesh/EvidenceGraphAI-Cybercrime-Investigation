"""Deterministic cryptographic hash chain computation and integrity verification for custody ledger."""

import hashlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from core.logging.logger import get_logger

logger = get_logger("core.custody.chain")

GENESIS_HASH = "0" * 64


class LedgerEntry(BaseModel):
    """Pydantic model representing a single immutable ledger record."""

    id: int | None = None
    evidence_id: str
    action: str
    actor: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    sha256: str
    previous_hash: str = GENESIS_HASH
    entry_hash: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    signature: str | None = None


class ChainVerificationResult(BaseModel):
    """Result of cryptographic ledger chain verification."""

    is_valid: bool
    total_entries: int
    broken_at_id: int | None = None
    message: str = "Chain is intact"
    error_details: dict[str, Any] | None = None


def canonical_serialize(data: dict[str, Any]) -> str:
    """Serializes a dictionary into a deterministic, sorted, compact JSON string.

    Args:
        data: Arbitrary dictionary.

    Returns:
        Canonical JSON string representation.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_entry_hash(
    evidence_id: str,
    action: str,
    actor: str,
    timestamp: str,
    sha256: str,
    previous_hash: str,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Computes deterministic SHA256 entry hash over all canonical fields including previous_hash.

    Args:
        evidence_id: Target evidence ID string.
        action: Ledger action type (e.g. INGEST, VERIFY).
        actor: Identity of actor performing the action.
        timestamp: ISO8601 UTC timestamp string.
        sha256: SHA256 hash of the evidence artifact.
        previous_hash: SHA256 hash of the immediately preceding ledger entry.
        metadata: Optional metadata dictionary.

    Returns:
        Hex-encoded SHA256 digest string.
    """
    canonical_payload = {
        "action": action,
        "actor": actor,
        "evidence_id": evidence_id,
        "metadata": metadata or {},
        "previous_hash": previous_hash,
        "sha256": sha256,
        "timestamp": timestamp,
    }
    serialized = canonical_serialize(canonical_payload)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def verify_chain(
    entries: Sequence[dict[str, Any] | LedgerEntry],
) -> ChainVerificationResult:
    """Verifies the cryptographic integrity of a sequence of ledger entries.

    Validates that:
    1. Each entry's entry_hash accurately reflects its canonical serialized contents.
    2. Each entry's previous_hash matches the previous entry's entry_hash (or GENESIS_HASH).

    Args:
        entries: Ordered list of ledger entries (oldest to newest).

    Returns:
        ChainVerificationResult object with verification details.
    """
    if not entries:
        return ChainVerificationResult(
            is_valid=True,
            total_entries=0,
            message="Ledger is empty; chain is trivially intact",
        )

    expected_prev_hash = GENESIS_HASH

    for idx, raw_entry in enumerate(entries):
        if isinstance(raw_entry, LedgerEntry):
            entry_dict = raw_entry.model_dump()
        else:
            entry_dict = dict(raw_entry)

        entry_id = entry_dict.get("id", idx + 1)
        evidence_id = str(entry_dict["evidence_id"])
        action = str(entry_dict["action"])
        actor = str(entry_dict["actor"])
        # Format timestamp to ISO string if it's a datetime object
        ts = entry_dict["timestamp"]
        ts_str = ts.isoformat() if isinstance(ts, datetime) else str(ts)

        sha256_val = str(entry_dict["sha256"])
        prev_hash = str(entry_dict.get("previous_hash", GENESIS_HASH))
        entry_hash = str(entry_dict["entry_hash"])
        meta = entry_dict.get("metadata") or {}

        # 1. Check previous_hash link continuity
        if prev_hash != expected_prev_hash:
            msg = (
                f"Chain break at entry ID {entry_id}: previous_hash '{prev_hash}' "
                f"does not match expected previous entry hash '{expected_prev_hash}'"
            )
            logger.warning(
                "Chain continuity break detected",
                entry_id=entry_id,
                prev_hash=prev_hash,
                expected=expected_prev_hash,
            )
            return ChainVerificationResult(
                is_valid=False,
                total_entries=len(entries),
                broken_at_id=entry_id,
                message=msg,
                error_details={
                    "entry_id": entry_id,
                    "expected_previous_hash": expected_prev_hash,
                    "actual_previous_hash": prev_hash,
                    "type": "CONTINUITY_BREAK",
                },
            )

        # 2. Recompute and check entry_hash integrity
        recomputed_hash = compute_entry_hash(
            evidence_id=evidence_id,
            action=action,
            actor=actor,
            timestamp=ts_str,
            sha256=sha256_val,
            previous_hash=prev_hash,
            metadata=meta,
        )

        if entry_hash != recomputed_hash:
            msg = (
                f"Tamper detected at entry ID {entry_id}: entry_hash '{entry_hash}' "
                f"does not match computed hash '{recomputed_hash}'"
            )
            logger.warning(
                "Entry hash tamper detected",
                entry_id=entry_id,
                stored=entry_hash,
                recomputed=recomputed_hash,
            )
            return ChainVerificationResult(
                is_valid=False,
                total_entries=len(entries),
                broken_at_id=entry_id,
                message=msg,
                error_details={
                    "entry_id": entry_id,
                    "expected_entry_hash": recomputed_hash,
                    "actual_entry_hash": entry_hash,
                    "type": "HASH_MISMATCH",
                },
            )

        expected_prev_hash = entry_hash

    return ChainVerificationResult(
        is_valid=True,
        total_entries=len(entries),
        message="Chain integrity successfully verified; all hashes and links match",
    )
