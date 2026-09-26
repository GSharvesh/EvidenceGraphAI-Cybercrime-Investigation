"""Unit tests for ArtifactIngestor pipeline with mocked storage, graph, and ledger."""

from unittest.mock import MagicMock

import pytest

from core.config.settings import Settings
from core.custody.chain import LedgerEntry
from core.custody.ledger import CustodyLedger
from core.graph.client import GraphClient
from core.ingestion.exceptions import FileTooLargeError
from core.ingestion.ingestor import ArtifactIngestor
from core.storage.minio_client import MinioClient
from scripts.seed_sample_artifacts import generate_sample_json, generate_sample_pcap


@pytest.fixture
def mock_storage() -> MagicMock:
    storage = MagicMock(spec=MinioClient)
    storage.bucket = "test-bucket"
    storage.put_object.return_value = "minio://test-bucket/evidence/EV-1/sha256"
    return storage


@pytest.fixture
def mock_graph() -> MagicMock:
    graph = MagicMock(spec=GraphClient)
    return graph


@pytest.fixture
def mock_ledger() -> MagicMock:
    ledger = MagicMock(spec=CustodyLedger)
    ledger.append_entry.return_value = LedgerEntry(
        id=1,
        evidence_id="EV-1",
        action="INGEST",
        actor="system",
        sha256="hash",
        entry_hash="ehash",
    )
    return ledger


@pytest.fixture
def ingestor(
    mock_settings: Settings,
    mock_storage: MagicMock,
    mock_graph: MagicMock,
    mock_ledger: MagicMock,
) -> ArtifactIngestor:
    return ArtifactIngestor(
        settings=mock_settings,
        storage_client=mock_storage,
        graph_client=mock_graph,
        custody_ledger=mock_ledger,
    )


def test_ingest_json_success(
    ingestor: ArtifactIngestor,
    mock_storage: MagicMock,
    mock_graph: MagicMock,
    mock_ledger: MagicMock,
) -> None:
    """Verifies end-to-end ingestion orchestration for JSON record."""
    json_bytes = generate_sample_json().encode("utf-8")

    result = ingestor.ingest(
        data_or_stream_or_path=json_bytes,
        filename="cve.json",
        actor="investigator-01",
    )

    assert result.evidence_id.startswith("EV-")
    assert result.artifact_type == "JSON"
    assert result.original_filename == "cve.json"
    assert result.file_size_bytes == len(json_bytes)
    mock_storage.put_object.assert_called_once()
    mock_graph.create_node.assert_called_once()
    mock_ledger.append_entry.assert_called_once()


def test_ingest_pcap_with_anonymization(
    ingestor: ArtifactIngestor, mock_storage: MagicMock, mock_ledger: MagicMock
) -> None:
    """Verifies PCAP ingestion applies DPDP filter and records ANONYMIZE entry."""
    pcap_bytes = generate_sample_pcap()

    result = ingestor.ingest(
        data_or_stream_or_path=pcap_bytes,
        filename="capture.pcap",
        anonymize=True,
    )

    assert result.artifact_type == "PCAP"
    assert result.anonymized is True
    assert result.original_sha256 is not None
    # Ledger should be called for ANONYMIZE and INGEST
    assert mock_ledger.append_entry.call_count >= 2


def test_ingest_file_too_large(ingestor: ArtifactIngestor) -> None:
    """Verifies file size exceeding limit raises FileTooLargeError."""
    # Set max size to 1MB and test 2MB
    ingestor.settings = ingestor.settings.model_copy(
        update={"ingestion_max_file_size_mb": 1}
    )
    big_bytes = b"0" * (2 * 1024 * 1024)

    with pytest.raises(FileTooLargeError):
        ingestor.ingest(data_or_stream_or_path=big_bytes, filename="big.bin")
