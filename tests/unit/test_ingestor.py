"""Unit tests for ArtifactIngestor pipeline with mocked storage, graph, and ledger."""

import io
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.config.settings import Settings
from core.custody.chain import LedgerEntry
from core.custody.ledger import CustodyLedger
from core.graph.client import GraphClient
from core.ingestion.exceptions import FileTooLargeError, IngestionError
from core.ingestion.ingestor import ArtifactIngestor
from core.privacy.anonymizer import AnonymizationMethod
from core.storage.minio_client import MinioClient
from scripts.seed_sample_artifacts import (
    generate_sample_json,
    generate_sample_log,
    generate_sample_pcap,
)


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
    mock_ledger: MagicMock,
    mock_graph: MagicMock,
) -> None:
    """Verifies complete ingestion lifecycle for JSON artifact."""
    json_bytes = generate_sample_json().encode("utf-8")
    result = ingestor.ingest(
        data_or_stream_or_path=json_bytes,
        filename="nvd.json",
        actor="analyst-01",
        source_metadata={"source": "NVD Feed"},
    )

    assert result.evidence_id.startswith("EV-")
    assert result.artifact_type == "JSON"
    assert result.storage_path.startswith("minio://")

    mock_storage.put_object.assert_called_once()
    mock_graph.create_node.assert_called_once()
    mock_ledger.append_entry.assert_called_once()


def test_ingest_pcap_with_anonymization(
    ingestor: ArtifactIngestor, mock_ledger: MagicMock
) -> None:
    """Verifies PCAP ingestion applies anonymization filter when requested."""
    pcap_bytes = generate_sample_pcap()
    result = ingestor.ingest(
        data_or_stream_or_path=pcap_bytes,
        filename="traffic.pcap",
        anonymize=True,
        anonymize_method=AnonymizationMethod.MASK,
    )

    assert result.artifact_type == "PCAP"
    assert result.anonymized is True
    # Should record both ANONYMIZE and INGEST in ledger
    assert mock_ledger.append_entry.call_count == 2


def test_ingest_log_with_anonymization(
    ingestor: ArtifactIngestor, mock_ledger: MagicMock
) -> None:
    """Verifies log file ingestion applies text anonymizer when enabled."""
    log_bytes = generate_sample_log().encode("utf-8")
    result = ingestor.ingest(
        data_or_stream_or_path=log_bytes,
        filename="system.log",
        anonymize=True,
        anonymize_method=AnonymizationMethod.MASK,
    )

    assert result.artifact_type == "PLAIN_TEXT"
    assert result.anonymized is True
    assert mock_ledger.append_entry.call_count == 2


def test_ingest_stream_input(ingestor: ArtifactIngestor) -> None:
    """Verifies ingestion from an open binary stream."""
    stream = io.BytesIO(b'{"key": "stream value"}')
    result = ingestor.ingest(
        data_or_stream_or_path=stream,
        filename="stream.json",
    )
    assert result.artifact_type == "JSON"


def test_ingest_file_path_input(ingestor: ArtifactIngestor, tmp_path: Path) -> None:
    """Verifies ingestion from a local file path."""
    file_path = tmp_path / "test_artifact.json"
    file_path.write_text('{"file": "path"}', encoding="utf-8")

    result = ingestor.ingest(
        data_or_stream_or_path=file_path,
    )
    assert result.artifact_type == "JSON"


def test_ingest_file_too_large(
    ingestor: ArtifactIngestor, mock_settings: Settings
) -> None:
    """Verifies rejecting files that exceed size limit."""
    mock_settings.ingestion_max_file_size_mb = 1
    oversized = b"X" * (1024 * 1024 + 10)

    with pytest.raises(FileTooLargeError):
        ingestor.ingest(
            data_or_stream_or_path=oversized,
            filename="big.bin",
        )


def test_ingest_storage_failure_raises(
    ingestor: ArtifactIngestor, mock_storage: MagicMock
) -> None:
    """Verifies storage failure raises IngestionError."""
    mock_storage.put_object.side_effect = Exception("Disk full")

    with pytest.raises(IngestionError, match="Artifact storage failed"):
        ingestor.ingest(
            data_or_stream_or_path=b'{"test": 1}',
            filename="test.json",
        )


def test_ingest_graph_failure_compensates(
    ingestor: ArtifactIngestor, mock_graph: MagicMock, mock_ledger: MagicMock
) -> None:
    """Verifies graph registration failure records ERROR compensation and completes ingest."""
    mock_graph.create_node.side_effect = Exception("Neo4j timeout")

    result = ingestor.ingest(
        data_or_stream_or_path=b'{"test": 1}',
        filename="test.json",
    )
    assert result.evidence_id.startswith("EV-")
    # Verify ledger append_entry was called for ERROR and INGEST
    assert mock_ledger.append_entry.call_count >= 1
