"""Unit tests for Phase 2 API endpoints using FastAPI TestClient and mocked dependencies."""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from api.dependencies import (
    get_artifact_ingestor,
    get_artifact_verifier,
    get_custody_ledger,
    get_manifest_generator,
    get_minio_client,
)
from api.main import app
from core.custody.chain import ChainVerificationResult, LedgerEntry
from core.custody.ledger import CustodyLedger
from core.custody.manifest import (
    EvidenceItemSummary,
    EvidenceManifest,
    ManifestGenerator,
)
from core.custody.verifier import (
    ArtifactVerifier,
    VerificationResult,
    VerificationStatus,
)
from core.ingestion.ingestor import ArtifactIngestor, IngestResult
from core.storage.minio_client import MinioClient


@pytest.fixture
def mock_ingestor_service() -> MagicMock:
    service = MagicMock(spec=ArtifactIngestor)
    service.ingest.return_value = IngestResult(
        evidence_id="EV-API-TEST-1",
        sha256="aabbcc112233",
        artifact_type="JSON",
        original_filename="test.json",
        file_size_bytes=100,
        storage_path="minio://bucket/evidence/EV-API-TEST-1/aabbcc112233",
        node_id="EV-API-TEST-1",
        ledger_entry_id=1,
    )
    return service


@pytest.fixture
def mock_ledger_service() -> MagicMock:
    service = MagicMock(spec=CustodyLedger)
    service.get_entries.return_value = [
        LedgerEntry(
            id=1,
            evidence_id="EV-API-TEST-1",
            action="INGEST",
            actor="test-actor",
            sha256="aabbcc112233",
            entry_hash="ehash1",
        )
    ]
    service.get_entries_for_evidence.return_value = [
        LedgerEntry(
            id=1,
            evidence_id="EV-API-TEST-1",
            action="INGEST",
            actor="test-actor",
            sha256="aabbcc112233",
            entry_hash="ehash1",
            metadata={"original_filename": "test.json", "detected_type": "JSON"},
        )
    ]
    service.verify_ledger_integrity.return_value = ChainVerificationResult(
        is_valid=True,
        total_entries=1,
        message="Chain intact",
    )
    service.get_ledger_stats.return_value = {
        "total_entries": 1,
        "total_evidence_items": 1,
        "action_counts": {"INGEST": 1},
        "latest_entry_timestamp": "2026-01-01T00:00:00+00:00",
    }
    return service


@pytest.fixture
def mock_verifier_service() -> MagicMock:
    service = MagicMock(spec=ArtifactVerifier)
    service.verify_artifact.return_value = VerificationResult(
        evidence_id="EV-API-TEST-1",
        status=VerificationStatus.MATCH,
        stored_sha256="aabbcc112233",
        recomputed_sha256="aabbcc112233",
        match=True,
        ledger_entry_id=2,
    )
    return service


@pytest.fixture
def mock_manifest_service() -> MagicMock:
    service = MagicMock(spec=ManifestGenerator)
    service.generate_manifest.return_value = EvidenceManifest(
        manifest_id="MANIFEST-TEST-1",
        generated_at="2026-01-01T00:00:00+00:00",
        generator_identity="Tester",
        evidence_count=1,
        evidence_items=[
            EvidenceItemSummary(
                evidence_id="EV-API-TEST-1",
                original_filename="test.json",
                sha256="aabbcc112233",
                artifact_type="JSON",
                storage_path="minio://bucket/evidence/EV-API-TEST-1/aabbcc112233",
                ingest_timestamp="2026-01-01T00:00:00+00:00",
                actor="test-actor",
            )
        ],
        chain_of_custody=[],
        ledger_integrity_status={
            "is_valid": True,
            "total_entries": 1,
            "message": "Intact",
        },
        digital_signature="test_signature",
    )
    service.verify_manifest.return_value = True
    return service


@pytest.fixture
def mock_storage_service() -> MagicMock:
    service = MagicMock(spec=MinioClient)
    service.bucket = "test-bucket"
    service.get_object_metadata.return_value = {
        "size": 100,
        "content_type": "application/json",
    }
    service.get_manifest.return_value = b'{"manifest_id":"MANIFEST-TEST-1","generated_at":"2026-01-01T00:00:00Z","generator_identity":"Tester","evidence_count":1,"evidence_items":[],"chain_of_custody":[],"ledger_integrity_status":{"is_valid":true},"signature_algorithm":"HMAC-SHA256","digital_signature":"sig"}'
    return service


def test_post_ingest(mock_ingestor_service: MagicMock) -> None:
    """Tests POST /ingest multipart upload."""
    app.dependency_overrides[get_artifact_ingestor] = lambda: mock_ingestor_service
    with TestClient(app) as client:
        file_content = b'{"cve": "CVE-2024-0001"}'
        response = client.post(
            "/ingest",
            files={"file": ("test.json", file_content, "application/json")},
            data={"actor": "investigator-01", "anonymize": "true"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["evidence_id"] == "EV-API-TEST-1"
        assert data["artifact_type"] == "JSON"
    app.dependency_overrides.clear()


def test_get_evidence(
    mock_ledger_service: MagicMock, mock_storage_service: MagicMock
) -> None:
    """Tests GET /evidence/{evidence_id}."""
    app.dependency_overrides[get_custody_ledger] = lambda: mock_ledger_service
    app.dependency_overrides[get_minio_client] = lambda: mock_storage_service
    with TestClient(app) as client:
        response = client.get("/evidence/EV-API-TEST-1")
        assert response.status_code == 200
        data = response.json()
        assert data["evidence_id"] == "EV-API-TEST-1"
        assert len(data["custody_chain"]) == 1
    app.dependency_overrides.clear()


def test_verify_evidence_endpoint(mock_verifier_service: MagicMock) -> None:
    """Tests GET /evidence/{evidence_id}/verify."""
    app.dependency_overrides[get_artifact_verifier] = lambda: mock_verifier_service
    with TestClient(app) as client:
        response = client.get("/evidence/EV-API-TEST-1/verify")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "MATCH"
        assert data["match"] is True
    app.dependency_overrides.clear()


def test_get_ledger_endpoints(mock_ledger_service: MagicMock) -> None:
    """Tests GET /ledger and GET /ledger/verify."""
    app.dependency_overrides[get_custody_ledger] = lambda: mock_ledger_service
    with TestClient(app) as client:
        # GET /ledger
        r1 = client.get("/ledger")
        assert r1.status_code == 200
        assert len(r1.json()["entries"]) == 1

        # GET /ledger/verify
        r2 = client.get("/ledger/verify")
        assert r2.status_code == 200
        assert r2.json()["is_valid"] is True
    app.dependency_overrides.clear()


def test_manifest_endpoints(
    mock_manifest_service: MagicMock, mock_storage_service: MagicMock
) -> None:
    """Tests POST /manifests, GET /manifests/{id}, and POST /manifests/verify."""
    app.dependency_overrides[get_manifest_generator] = lambda: mock_manifest_service
    app.dependency_overrides[get_minio_client] = lambda: mock_storage_service
    with TestClient(app) as client:
        # POST /manifests
        r1 = client.post("/manifests", json={"evidence_ids": ["EV-API-TEST-1"]})
        assert r1.status_code == 201
        manifest = r1.json()
        assert manifest["manifest_id"] == "MANIFEST-TEST-1"

        # POST /manifests with custom legal framework
        r1_custom = client.post(
            "/manifests",
            json={
                "evidence_ids": ["EV-API-TEST-1"],
                "legal_framework": "Section 63 Bharatiya Sakshya Adhiniyam, 2023 / BNSS 2023",
                "generator_identity": "State Forensics Laboratory",
            },
        )
        assert r1_custom.status_code == 201

        # POST /manifests with Ed25519 algorithm
        r1_ed25519 = client.post(
            "/manifests",
            json={
                "evidence_ids": ["EV-API-TEST-1"],
                "signature_algorithm": "Ed25519",
                "generator_identity": "State Forensics Laboratory",
            },
        )
        assert r1_ed25519.status_code == 201

        # GET /manifests/MANIFEST-TEST-1
        r2 = client.get("/manifests/MANIFEST-TEST-1")
        assert r2.status_code == 200

        # POST /manifests/verify
        r3 = client.post("/manifests/verify", json=manifest)
        assert r3.status_code == 200
        assert r3.json()["is_valid"] is True

        # POST /manifests/verify with public_key query parameter rejects HMAC manifest (algorithm confusion defense)
        r4 = client.post("/manifests/verify?public_key=aabbcc112233", json=manifest)
        assert r4.status_code == 200
        assert r4.json()["is_valid"] is False
        assert "Algorithm confusion rejected" in r4.json()["message"]

        # POST /manifests/verify with public_key query parameter succeeds for Ed25519 manifest
        ed_manifest = dict(manifest, signature_algorithm="Ed25519")
        r5 = client.post("/manifests/verify?public_key=aabbcc112233", json=ed_manifest)
        assert r5.status_code == 200
        assert r5.json()["is_valid"] is True
    app.dependency_overrides.clear()


def test_serve_ingestion_portal() -> None:
    """Tests GET /dev/ingestion-portal serves HTML."""
    with TestClient(app) as client:
        response = client.get("/dev/ingestion-portal")
        assert response.status_code == 200
        assert "Forensic Ingest Console" in response.text
