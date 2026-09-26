"""Integration tests for forensic artifact ingestion pipeline."""

from core.custody.ledger import CustodyLedger
from core.custody.verifier import ArtifactVerifier, VerificationStatus
from core.db.postgres import PostgresClient
from core.graph.client import GraphClient
from core.ingestion.ingestor import ArtifactIngestor
from core.storage.minio_client import MinioClient
from scripts.seed_sample_artifacts import (
    generate_sample_apk,
    generate_sample_certificates,
    generate_sample_json,
    generate_sample_log,
    generate_sample_pcap,
    generate_sample_pe,
)
from tests.integration.conftest import (
    minio_required,
    neo4j_required,
    postgres_required,
)


@minio_required
@postgres_required
@neo4j_required
def test_ingest_all_artifact_types(
    test_client: GraphClient,
    test_postgres: PostgresClient,
    test_storage: MinioClient,
    clean_test_graph: None,
) -> None:
    """Verifies end-to-end ingestion and verification across all supported forensic artifact formats."""
    ledger = CustodyLedger(db_client=test_postgres)
    ingestor = ArtifactIngestor(
        storage_client=test_storage,
        graph_client=test_client,
        custody_ledger=ledger,
    )
    verifier = ArtifactVerifier(
        storage_client=test_storage,
        custody_ledger=ledger,
    )

    artifacts_to_test = [
        ("TestPhase2_pcap.pcap", generate_sample_pcap(), "PCAP"),
        ("TestPhase2_cve.json", generate_sample_json().encode("utf-8"), "JSON"),
        ("TestPhase2_binary.exe", generate_sample_pe(), "PE"),
        ("TestPhase2_app.apk", generate_sample_apk(), "APK"),
        ("TestPhase2_system.log", generate_sample_log().encode("utf-8"), "PLAIN_TEXT"),
    ]

    pem_str, der_bytes = generate_sample_certificates()
    artifacts_to_test.append(
        ("TestPhase2_cert.pem", pem_str.encode("utf-8"), "CERT_PEM")
    )
    artifacts_to_test.append(("TestPhase2_cert.der", der_bytes, "CERT_DER"))

    for filename, raw_bytes, expected_type in artifacts_to_test:
        result = ingestor.ingest(
            data_or_stream_or_path=raw_bytes,
            filename=filename,
            actor="integration_agent",
            anonymize=False,
        )

        assert result.evidence_id.startswith("EV-")
        assert result.artifact_type == expected_type
        assert result.file_size_bytes == len(raw_bytes)
        assert test_storage.object_exists(result.evidence_id, result.sha256) is True

        # Verify artifact hash with verifier service
        verify_res = verifier.verify_artifact(result.evidence_id)
        assert verify_res.status == VerificationStatus.MATCH
        assert verify_res.match is True
