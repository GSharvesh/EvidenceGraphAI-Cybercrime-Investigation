"""Demonstration of Chain of Custody hash-chain tamper detection."""

from core.custody.chain import (
    GENESIS_HASH,
    LedgerEntry,
    compute_entry_hash,
    verify_chain,
)


def run_tamper_demo() -> None:
    print("=" * 70)
    print("CHAIN OF CUSTODY HASH-CHAIN TAMPER DETECTION DEMO")
    print("=" * 70)

    # 1. Genesis Hash
    print(f"\n[1] Genesis Hash: {GENESIS_HASH}")

    # 2. Construct 3 legitimate custody ledger records with cryptographic chaining
    t1 = "2026-09-26T10:00:00+00:00"
    sha_art = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    h1 = compute_entry_hash(
        evidence_id="EV-DEMO-2026-001",
        action="INGEST",
        actor="forensic-analyst-01",
        timestamp=t1,
        sha256=sha_art,
        previous_hash=GENESIS_HASH,
        metadata={"source": "Seized Laptop Hard Drive"},
    )
    entry1 = LedgerEntry(
        id=1,
        evidence_id="EV-DEMO-2026-001",
        action="INGEST",
        actor="forensic-analyst-01",
        timestamp=t1,
        sha256=sha_art,
        previous_hash=GENESIS_HASH,
        entry_hash=h1,
        metadata={"source": "Seized Laptop Hard Drive"},
    )
    print(
        f"[2] Record 1 (INGEST): entry_hash={h1[:16]}... previous_hash={GENESIS_HASH[:16]}..."
    )

    t2 = "2026-09-26T10:05:00+00:00"
    h2 = compute_entry_hash(
        evidence_id="EV-DEMO-2026-001",
        action="ANONYMIZE",
        actor="dpdp-privacy-filter",
        timestamp=t2,
        sha256=sha_art,
        previous_hash=h1,
        metadata={"method": "MASK", "pii_count": 4},
    )
    entry2 = LedgerEntry(
        id=2,
        evidence_id="EV-DEMO-2026-001",
        action="ANONYMIZE",
        actor="dpdp-privacy-filter",
        timestamp=t2,
        sha256=sha_art,
        previous_hash=h1,
        entry_hash=h2,
        metadata={"method": "MASK", "pii_count": 4},
    )
    print(
        f"[3] Record 2 (ANONYMIZE): entry_hash={h2[:16]}... previous_hash={h1[:16]}..."
    )

    t3 = "2026-09-26T10:15:00+00:00"
    h3 = compute_entry_hash(
        evidence_id="EV-DEMO-2026-001",
        action="EXPORT",
        actor="lead-investigator",
        timestamp=t3,
        sha256=sha_art,
        previous_hash=h2,
        metadata={
            "export_target": "Court Manifest 65B",
            "manifest_id": "MAN-65B-2026-001",
        },
    )
    entry3 = LedgerEntry(
        id=3,
        evidence_id="EV-DEMO-2026-001",
        action="EXPORT",
        actor="lead-investigator",
        timestamp=t3,
        sha256=sha_art,
        previous_hash=h2,
        entry_hash=h3,
        metadata={
            "export_target": "Court Manifest 65B",
            "manifest_id": "MAN-65B-2026-001",
        },
    )
    print(f"[4] Record 3 (EXPORT): entry_hash={h3[:16]}... previous_hash={h2[:16]}...")

    entries = [entry1, entry2, entry3]

    # 3. Verify legitimate chain
    res = verify_chain(entries)
    print(
        f"\n[5] Initial Chain Verification: is_valid={res.is_valid}, message={res.message}"
    )
    assert res.is_valid is True, "Legitimate chain must verify"

    # 4. Tamper with Record 2 payload (e.g. malicious actor changes actor)
    print("\n[6] SIMULATING TAMPERING ATTACK:")
    print(
        "    Attacker modifies Record 2 actor from 'dpdp-privacy-filter' to 'unauthorized-user'"
    )
    tampered_entry2 = LedgerEntry(
        id=2,
        evidence_id="EV-DEMO-2026-001",
        action="ANONYMIZE",
        actor="unauthorized-user",  # Tampered payload
        timestamp=t2,
        sha256=sha_art,
        previous_hash=h1,
        entry_hash=h2,  # Stale/unrecomputed hash
        metadata={"method": "MASK", "pii_count": 4},
    )
    tampered_entries = [entry1, tampered_entry2, entry3]

    res_tampered = verify_chain(tampered_entries)
    print(f"    Tampered Chain Verification Result: is_valid={res_tampered.is_valid}")
    print(f"    Tamper Detection Message: {res_tampered.message}")
    print(f"    Broken At Entry ID: {res_tampered.broken_at_id}")
    assert res_tampered.is_valid is False, "Tampered chain must fail verification"
    assert res_tampered.broken_at_id == 2

    # 5. Tamper with Hash Chaining Link (Broken Previous Hash)
    print("\n[7] SIMULATING HASH-POINTER SPLICING ATTACK:")
    print("    Attacker tries to splice in forged previous_hash on Record 3")
    spliced_entry3 = LedgerEntry(
        id=3,
        evidence_id="EV-DEMO-2026-001",
        action="EXPORT",
        actor="lead-investigator",
        timestamp=t3,
        sha256=sha_art,
        previous_hash="deadbeef" * 8,  # Broken hash link
        entry_hash=h3,
        metadata={
            "export_target": "Court Manifest 65B",
            "manifest_id": "MAN-65B-2026-001",
        },
    )
    spliced_entries = [entry1, entry2, spliced_entry3]

    res_spliced = verify_chain(spliced_entries)
    print(f"    Spliced Chain Verification Result: is_valid={res_spliced.is_valid}")
    print(f"    Splice Detection Message: {res_spliced.message}")
    print(f"    Broken At Entry ID: {res_spliced.broken_at_id}")
    assert res_spliced.is_valid is False, "Spliced chain must fail verification"
    assert res_spliced.broken_at_id == 3

    print("\n" + "=" * 70)
    print(
        "VERDICT: Chain of custody cryptographic verification successfully detected both payload tampering and hash-pointer splicing attacks."
    )
    print("=" * 70)


if __name__ == "__main__":
    run_tamper_demo()
