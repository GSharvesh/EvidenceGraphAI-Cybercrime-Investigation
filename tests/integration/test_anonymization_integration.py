"""Integration tests for DPDP Act 2023 anonymization pipeline."""

from core.custody.ledger import CustodyLedger
from core.db.postgres import PostgresClient
from core.graph.client import GraphClient
from core.ingestion.ingestor import ArtifactIngestor
from core.privacy.anonymizer import AnonymizationMethod
from core.storage.minio_client import MinioClient
from scripts.seed_sample_artifacts import generate_sample_log
from tests.integration.conftest import (
    minio_required,
    neo4j_required,
    postgres_required,
)


@minio_required
@postgres_required
@neo4j_required
def test_anonymization_ingest_integration(
    test_client: GraphClient,
    test_postgres: PostgresClient,
    test_storage: MinioClient,
    clean_test_graph: None,
) -> None:
    """Verifies that anonymized artifacts record ANONYMIZE entries and persist scrubbed content."""
    ledger = CustodyLedger(db_client=test_postgres)
    ingestor = ArtifactIngestor(
        storage_client=test_storage,
        graph_client=test_client,
        custody_ledger=ledger,
    )

    log_bytes = generate_sample_log().encode("utf-8")
    result = ingestor.ingest(
        data_or_stream_or_path=log_bytes,
        filename="TestPhase2_anonymized.log",
        anonymize=True,
        anonymize_method=AnonymizationMethod.MASK,
    )

    assert result.anonymized is True
    assert result.anonymization_stats is not None

    # Check ledger history contains both ANONYMIZE and INGEST
    entries = ledger.get_entries_for_evidence(result.evidence_id)
    actions = [e.action for e in entries]
    assert "ANONYMIZE" in actions
    assert "INGEST" in actions

    # Download from storage and ensure PII was masked
    stored_bytes = test_storage.get_object(result.evidence_id, result.sha256)
    stored_text = stored_bytes.decode("utf-8")
    assert "vikram.sharma@domain.in" not in stored_text
    assert "3456 7890 1234" not in stored_text
