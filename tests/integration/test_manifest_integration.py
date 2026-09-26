"""Integration tests for Section 65B Evidence Manifest generation and verification."""

from core.custody.ledger import CustodyLedger
from core.custody.manifest import ManifestGenerator
from core.db.postgres import PostgresClient
from core.graph.client import GraphClient
from core.ingestion.ingestor import ArtifactIngestor
from core.storage.minio_client import MinioClient
from scripts.seed_sample_artifacts import generate_sample_json
from tests.integration.conftest import (
    minio_required,
    neo4j_required,
    postgres_required,
)


@minio_required
@postgres_required
@neo4j_required
def test_generate_and_verify_manifest_integration(
    test_client: GraphClient,
    test_postgres: PostgresClient,
    test_storage: MinioClient,
    clean_test_graph: None,
) -> None:
    """Verifies end-to-end manifest generation, digital signing, and archival in MinIO."""
    ledger = CustodyLedger(db_client=test_postgres)
    ingestor = ArtifactIngestor(
        storage_client=test_storage,
        graph_client=test_client,
        custody_ledger=ledger,
    )
    generator = ManifestGenerator(
        custody_ledger=ledger,
        storage_client=test_storage,
    )

    ingest_res = ingestor.ingest(
        data_or_stream_or_path=generate_sample_json().encode("utf-8"),
        filename="TestPhase2_manifest_sample.json",
        actor="forensic_officer",
    )

    manifest = generator.generate_manifest(
        evidence_ids=[ingest_res.evidence_id],
        generator_identity="Chief Forensic Examiner",
        actor="forensic_officer",
    )

    assert manifest.manifest_id.startswith("MANIFEST-")
    assert manifest.evidence_count == 1
    assert manifest.evidence_items[0].evidence_id == ingest_res.evidence_id
    assert manifest.digital_signature != ""

    # Check verification
    is_valid = generator.verify_manifest(manifest)
    assert is_valid is True

    # Retrieve from storage
    stored_manifest_bytes = test_storage.get_manifest(manifest.manifest_id)
    assert len(stored_manifest_bytes) > 0
