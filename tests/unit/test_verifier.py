"""Unit tests for ArtifactVerifier service."""

import hashlib
from unittest.mock import MagicMock

import pytest

from core.custody.chain import LedgerEntry
from core.custody.ledger import CustodyLedger
from core.custody.verifier import ArtifactVerifier, VerificationStatus
from core.storage.exceptions import ObjectNotFoundError
from core.storage.minio_client import MinioClient


@pytest.fixture
def mock_storage() -> MagicMock:
    """Returns mocked MinioClient."""
    return MagicMock(spec=MinioClient)


@pytest.fixture
def mock_ledger() -> MagicMock:
    """Returns mocked CustodyLedger."""
    return MagicMock(spec=CustodyLedger)


@pytest.fixture
def verifier(mock_storage: MagicMock, mock_ledger: MagicMock) -> ArtifactVerifier:
    """Returns ArtifactVerifier initialized with mocked dependencies."""
    return ArtifactVerifier(storage_client=mock_storage, custody_ledger=mock_ledger)


def test_verify_artifact_pass(
    verifier: ArtifactVerifier, mock_storage: MagicMock, mock_ledger: MagicMock
) -> None:
    """Verifies that pristine artifact recomputation matches ledger hash."""
    artifact_bytes = b"Pristine PCAP content 2026"
    expected_sha = hashlib.sha256(artifact_bytes).hexdigest()

    mock_ledger.get_entries_for_evidence.return_value = [
        LedgerEntry(
            id=1,
            evidence_id="EV-1",
            action="INGEST",
            actor="agent-1",
            sha256=expected_sha,
            previous_hash="0" * 64,
            entry_hash="entryhash1",
        )
    ]
    mock_storage.get_object.return_value = artifact_bytes
    mock_ledger.append_entry.return_value = LedgerEntry(
        id=2,
        evidence_id="EV-1",
        action="VERIFY",
        actor="system",
        sha256=expected_sha,
        entry_hash="entryhash2",
    )

    result = verifier.verify_artifact("EV-1")
    assert result.status == VerificationStatus.MATCH
    assert result.match is True
    assert result.recomputed_sha256 == expected_sha
    mock_ledger.append_entry.assert_called_once()


def test_verify_artifact_mismatch(
    verifier: ArtifactVerifier, mock_storage: MagicMock, mock_ledger: MagicMock
) -> None:
    """Verifies that altered artifact content triggers MISMATCH."""
    original_bytes = b"Original Content"
    tampered_bytes = b"Tampered Content In Vault"
    original_sha = hashlib.sha256(original_bytes).hexdigest()

    mock_ledger.get_entries_for_evidence.return_value = [
        LedgerEntry(
            id=1,
            evidence_id="EV-1",
            action="INGEST",
            actor="agent-1",
            sha256=original_sha,
            entry_hash="entryhash1",
        )
    ]
    mock_storage.get_object.return_value = tampered_bytes

    result = verifier.verify_artifact("EV-1")
    assert result.status == VerificationStatus.MISMATCH
    assert result.match is False
    assert result.recomputed_sha256 != original_sha


def test_verify_artifact_not_in_ledger(
    verifier: ArtifactVerifier, mock_ledger: MagicMock
) -> None:
    """Verifies NOT_FOUND when evidence ID does not exist in ledger."""
    mock_ledger.get_entries_for_evidence.return_value = []
    result = verifier.verify_artifact("EV-NONEXISTENT")
    assert result.status == VerificationStatus.NOT_FOUND
    assert result.match is False


def test_verify_artifact_missing_in_storage(
    verifier: ArtifactVerifier, mock_storage: MagicMock, mock_ledger: MagicMock
) -> None:
    """Verifies NOT_FOUND when artifact is recorded in ledger but missing from object storage."""
    mock_ledger.get_entries_for_evidence.return_value = [
        LedgerEntry(
            id=1,
            evidence_id="EV-1",
            action="INGEST",
            actor="agent",
            sha256="aabbcc",
            entry_hash="ehash",
        )
    ]
    mock_storage.get_object.side_effect = ObjectNotFoundError("Object not found")

    result = verifier.verify_artifact("EV-1")
    assert result.status == VerificationStatus.NOT_FOUND
    assert result.match is False
