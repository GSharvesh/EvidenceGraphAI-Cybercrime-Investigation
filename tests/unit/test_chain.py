"""Unit tests for cryptographic hash chain computation and integrity verification."""

from core.custody.chain import (
    GENESIS_HASH,
    canonical_serialize,
    compute_entry_hash,
    verify_chain,
)


def test_canonical_serialize_deterministic() -> None:
    """Verifies that canonical serialization produces identical output regardless of key order."""
    d1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    d2 = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}
    assert canonical_serialize(d1) == canonical_serialize(d2)
    assert canonical_serialize(d1) == '{"a":2,"m":{"a":4,"b":3},"z":1}'


def test_compute_entry_hash_known() -> None:
    """Verifies deterministic entry hash computation."""
    h = compute_entry_hash(
        evidence_id="EV-1",
        action="INGEST",
        actor="system",
        timestamp="2026-01-01T00:00:00+00:00",
        sha256="aabbccddeeff",
        previous_hash=GENESIS_HASH,
        metadata={"filename": "test.pcap"},
    )
    assert isinstance(h, str)
    assert len(h) == 64


def test_verify_chain_valid_sequence() -> None:
    """Verifies that a valid multi-entry chain passes integrity verification."""
    entries: list[dict] = []
    prev_hash = GENESIS_HASH

    for i in range(1, 5):
        ts = f"2026-01-0{i}T00:00:00+00:00"
        eh = compute_entry_hash(
            evidence_id=f"EV-{i}",
            action="INGEST",
            actor="agent-1",
            timestamp=ts,
            sha256=f"hash_{i}",
            previous_hash=prev_hash,
            metadata={"step": i},
        )
        entries.append(
            {
                "id": i,
                "evidence_id": f"EV-{i}",
                "action": "INGEST",
                "actor": "agent-1",
                "timestamp": ts,
                "sha256": f"hash_{i}",
                "previous_hash": prev_hash,
                "entry_hash": eh,
                "metadata": {"step": i},
            }
        )
        prev_hash = eh

    res = verify_chain(entries)
    assert res.is_valid is True
    assert res.total_entries == 4
    assert res.broken_at_id is None


def test_verify_chain_detects_tampered_payload() -> None:
    """Verifies that tampering with any field in a block is detected."""
    entries: list[dict] = []
    prev_hash = GENESIS_HASH

    for i in range(1, 4):
        ts = f"2026-01-0{i}T00:00:00+00:00"
        eh = compute_entry_hash(
            evidence_id=f"EV-{i}",
            action="INGEST",
            actor="agent-1",
            timestamp=ts,
            sha256=f"hash_{i}",
            previous_hash=prev_hash,
        )
        entries.append(
            {
                "id": i,
                "evidence_id": f"EV-{i}",
                "action": "INGEST",
                "actor": "agent-1",
                "timestamp": ts,
                "sha256": f"hash_{i}",
                "previous_hash": prev_hash,
                "entry_hash": eh,
            }
        )
        prev_hash = eh

    # Tamper with entry 2 actor field
    entries[1]["actor"] = "malicious_actor"

    res = verify_chain(entries)
    assert res.is_valid is False
    assert res.broken_at_id == 2
    assert res.error_details["type"] == "HASH_MISMATCH"


def test_verify_chain_detects_broken_continuity() -> None:
    """Verifies that a break in the previous_hash link is detected."""
    entries: list[dict] = []
    prev_hash = GENESIS_HASH

    for i in range(1, 4):
        ts = f"2026-01-0{i}T00:00:00+00:00"
        eh = compute_entry_hash(
            evidence_id=f"EV-{i}",
            action="INGEST",
            actor="agent-1",
            timestamp=ts,
            sha256=f"hash_{i}",
            previous_hash=prev_hash,
        )
        entries.append(
            {
                "id": i,
                "evidence_id": f"EV-{i}",
                "action": "INGEST",
                "actor": "agent-1",
                "timestamp": ts,
                "sha256": f"hash_{i}",
                "previous_hash": prev_hash,
                "entry_hash": eh,
            }
        )
        prev_hash = eh

    # Alter previous_hash of entry 3 to simulate deleted/inserted intermediate block
    entries[2]["previous_hash"] = "0" * 64
    entries[2]["entry_hash"] = compute_entry_hash(
        evidence_id="EV-3",
        action="INGEST",
        actor="agent-1",
        timestamp="2026-01-03T00:00:00+00:00",
        sha256="hash_3",
        previous_hash="0" * 64,
    )

    res = verify_chain(entries)
    assert res.is_valid is False
    assert res.broken_at_id == 3
    assert res.error_details["type"] == "CONTINUITY_BREAK"


def test_verify_chain_detects_reordered_entries() -> None:
    """Verifies that reordering blocks in the chain breaks continuity."""
    entries: list[dict] = []
    prev_hash = GENESIS_HASH

    for i in range(1, 4):
        ts = f"2026-01-0{i}T00:00:00+00:00"
        eh = compute_entry_hash(
            evidence_id=f"EV-{i}",
            action="INGEST",
            actor="agent-1",
            timestamp=ts,
            sha256=f"hash_{i}",
            previous_hash=prev_hash,
        )
        entries.append(
            {
                "id": i,
                "evidence_id": f"EV-{i}",
                "action": "INGEST",
                "actor": "agent-1",
                "timestamp": ts,
                "sha256": f"hash_{i}",
                "previous_hash": prev_hash,
                "entry_hash": eh,
            }
        )
        prev_hash = eh

    # Swap entries 1 and 2
    reordered = [entries[0], entries[2], entries[1]]
    res = verify_chain(reordered)
    assert res.is_valid is False


def test_verify_chain_detects_tampered_metadata() -> None:
    """Verifies that mutating metadata dict breaks entry hash verification."""
    ts = "2026-01-01T00:00:00+00:00"
    eh = compute_entry_hash(
        evidence_id="EV-1",
        action="INGEST",
        actor="agent-1",
        timestamp=ts,
        sha256="hash_1",
        previous_hash=GENESIS_HASH,
        metadata={"key": "original"},
    )
    entry = {
        "id": 1,
        "evidence_id": "EV-1",
        "action": "INGEST",
        "actor": "agent-1",
        "timestamp": ts,
        "sha256": "hash_1",
        "previous_hash": GENESIS_HASH,
        "entry_hash": eh,
        "metadata": {"key": "tampered"},
    }
    res = verify_chain([entry])
    assert res.is_valid is False
    assert res.broken_at_id == 1
    assert res.error_details["type"] == "HASH_MISMATCH"


def test_verify_chain_detects_tampered_timestamp() -> None:
    """Verifies that changing timestamp in entry breaks hash verification."""
    ts = "2026-01-01T00:00:00+00:00"
    eh = compute_entry_hash(
        evidence_id="EV-1",
        action="INGEST",
        actor="agent-1",
        timestamp=ts,
        sha256="hash_1",
        previous_hash=GENESIS_HASH,
    )
    entry = {
        "id": 1,
        "evidence_id": "EV-1",
        "action": "INGEST",
        "actor": "agent-1",
        "timestamp": "2026-01-02T00:00:00+00:00",
        "sha256": "hash_1",
        "previous_hash": GENESIS_HASH,
        "entry_hash": eh,
    }
    res = verify_chain([entry])
    assert res.is_valid is False


def test_verify_chain_empty_ledger() -> None:
    """Verifies that an empty ledger sequence passes verification trivially."""
    res = verify_chain([])
    assert res.is_valid is True
    assert res.total_entries == 0
