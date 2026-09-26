"""Unit tests for Section 65B Evidence Manifest generator and verifier."""

from unittest.mock import MagicMock

import pytest

from core.config.settings import Settings
from core.custody.chain import ChainVerificationResult, LedgerEntry
from core.custody.exceptions import ManifestGenerationError
from core.custody.ledger import CustodyLedger
from core.custody.manifest import ManifestGenerator
from core.storage.minio_client import MinioClient


@pytest.fixture
def mock_storage() -> MagicMock:
    storage = MagicMock(spec=MinioClient)
    storage.bucket = "test-bucket"
    storage.put_manifest.return_value = "minio://test-bucket/manifests/MANIFEST-1.json"
    return storage


@pytest.fixture
def mock_ledger() -> MagicMock:
    ledger = MagicMock(spec=CustodyLedger)
    ledger.get_entries_for_evidence.return_value = [
        LedgerEntry(
            id=1,
            evidence_id="EV-1",
            action="INGEST",
            actor="agent-1",
            timestamp="2026-01-01T00:00:00+00:00",
            sha256="aabbccddeeff",
            previous_hash="0" * 64,
            entry_hash="entryhash1",
            metadata={"original_filename": "evidence.pcap", "detected_type": "PCAP"},
        )
    ]
    ledger.verify_ledger_integrity.return_value = ChainVerificationResult(
        is_valid=True,
        total_entries=1,
        message="Chain intact",
    )
    return ledger


@pytest.fixture
def manifest_gen(
    mock_settings: Settings, mock_ledger: MagicMock, mock_storage: MagicMock
) -> ManifestGenerator:
    return ManifestGenerator(
        settings=mock_settings,
        custody_ledger=mock_ledger,
        storage_client=mock_storage,
    )


def test_generate_manifest_success(
    manifest_gen: ManifestGenerator, mock_storage: MagicMock, mock_ledger: MagicMock
) -> None:
    """Verifies that generate_manifest produces Section 65B declaration, items, chain, and signature."""
    manifest = manifest_gen.generate_manifest(
        evidence_ids=["EV-1"],
        generator_identity="Chief Forensic Examiner",
        actor="examiner-01",
    )

    assert manifest.manifest_id.startswith("MANIFEST-")
    assert manifest.evidence_count == 1
    assert len(manifest.evidence_items) == 1
    assert manifest.evidence_items[0].evidence_id == "EV-1"
    assert "SECTION 65B" in manifest.legal_declaration
    assert manifest.digital_signature != ""
    assert manifest.ledger_integrity_status["is_valid"] is True
    mock_storage.put_manifest.assert_called_once()
    mock_ledger.append_entry.assert_called_once()


def test_verify_manifest_signature(manifest_gen: ManifestGenerator) -> None:
    """Verifies HMAC signature verification passes on untouched manifest and fails on altered manifest."""
    manifest = manifest_gen.generate_manifest(evidence_ids=["EV-1"])
    assert manifest_gen.verify_manifest(manifest) is True

    # Tamper with generator identity
    manifest_tampered = manifest.model_copy(update={"generator_identity": "Impostor"})
    assert manifest_gen.verify_manifest(manifest_tampered) is False


def test_generate_manifest_empty_list_raises(manifest_gen: ManifestGenerator) -> None:
    """Verifies empty evidence list raises ManifestGenerationError."""
    with pytest.raises(ManifestGenerationError):
        manifest_gen.generate_manifest(evidence_ids=[])
