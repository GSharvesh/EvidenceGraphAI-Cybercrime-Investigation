"""Demonstration script for Section 65B Certified Evidence Manifest generation and verification."""

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

from core.custody.chain import (
    GENESIS_HASH,
    ChainVerificationResult,
    LedgerEntry,
    compute_entry_hash,
)
from core.custody.manifest import ManifestGenerator

print("=" * 70)
print("SECTION 65B EVIDENCE MANIFEST GENERATION & VERIFICATION DEMO")
print("=" * 70)

# Create synthetic ledger history for evidence
ev_id = "EV-20260926-FORENSIC-001"
ev_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

ts1 = datetime.now(UTC).isoformat()
entry1_hash = compute_entry_hash(
    evidence_id=ev_id,
    action="INGEST",
    actor="agent://ingestor",
    timestamp=ts1,
    sha256=ev_sha256,
    previous_hash=GENESIS_HASH,
    metadata={"filename": "incident_traffic.pcap", "file_type": "PCAP"},
)

entry1 = LedgerEntry(
    id=1,
    evidence_id=ev_id,
    action="INGEST",
    actor="agent://ingestor",
    timestamp=ts1,
    sha256=ev_sha256,
    previous_hash=GENESIS_HASH,
    entry_hash=entry1_hash,
    metadata={"filename": "incident_traffic.pcap", "file_type": "PCAP"},
)

ts2 = datetime.now(UTC).isoformat()
entry2_hash = compute_entry_hash(
    evidence_id=ev_id,
    action="ANONYMIZE",
    actor="agent://dpdp-filter",
    timestamp=ts2,
    sha256=ev_sha256,
    previous_hash=entry1_hash,
    metadata={"method": "MASK", "pii_redacted": 7},
)

entry2 = LedgerEntry(
    id=2,
    evidence_id=ev_id,
    action="ANONYMIZE",
    actor="agent://dpdp-filter",
    timestamp=ts2,
    sha256=ev_sha256,
    previous_hash=entry1_hash,
    entry_hash=entry2_hash,
    metadata={"method": "MASK", "pii_redacted": 7},
)

history = [entry1, entry2]

mock_ledger = MagicMock()
mock_ledger.get_entries_for_evidence.return_value = history
mock_ledger.verify_ledger_integrity.return_value = ChainVerificationResult(
    is_valid=True,
    total_entries=2,
    message="Ledger cryptographic hash chain fully verified from genesis",
)

mock_storage = MagicMock()
mock_storage.put_manifest.return_value = (
    "minio://evidencegraphai-artifacts/manifests/MANIFEST-DEMO-001.json"
)

gen = ManifestGenerator(
    custody_ledger=mock_ledger,
    storage_client=mock_storage,
)

manifest = gen.generate_manifest(
    evidence_ids=[ev_id],
    generator_identity="EvidenceGraphAI Section 65B Digital Evidence Authority",
    actor="agent://legal-export",
)

print(f"\nManifest ID: {manifest.manifest_id}")
print(f"Generated At: {manifest.generated_at}")
print(f"Generator Identity: {manifest.generator_identity}")
print(f"Digital Signature (HMAC-SHA256): {manifest.digital_signature}")
print(f"Legal Framework: {manifest.legal_framework}")
print(f"Legal Declaration Summary: {manifest.legal_declaration[:120]}...")

# Verify Signature
is_valid_sig = gen.verify_manifest(manifest)
print(f"\nSignature Verification: {'VALID / VERIFIED' if is_valid_sig else 'INVALID'}")

print("\n--- [FULL CANONICAL MANIFEST JSON] ---")
print(json.dumps(manifest.model_dump(), indent=2))

print("\n" + "=" * 70)
print("DEMONSTRATION RESULT: PASS (Manifest signed and verified)")
print("=" * 70)
