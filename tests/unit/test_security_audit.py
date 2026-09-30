"""Adversarial security audit tests covering cryptographic, custody, storage, and API defenses."""

import hashlib
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.main import app
from api.routes.graph import _guard_dev_endpoint
from core.config.settings import Settings
from core.custody.chain import (
    ChainVerificationResult,
    LedgerEntry,
    canonical_serialize,
)
from core.custody.manifest import (
    ManifestGenerator,
    generate_ed25519_keypair,
)
from core.custody.verifier import ArtifactVerifier, VerificationStatus
from core.storage.minio_client import MinioClient


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        app_env="testing",
        manifest_signing_key="audit-test-secret-key-at-least-32b!",
        dev_viewer_enabled=True,
        dev_viewer_allow_remote=False,
    )


# --- 1. Algorithm Confusion / Downgrade Attack Defense ---


def test_algorithm_confusion_downgrade_rejected(test_settings: Settings) -> None:
    """Verifies that an attacker cannot forge an HMAC-SHA256 signature using an Ed25519 public key as HMAC secret."""
    _, pub_hex = generate_ed25519_keypair()

    mock_ledger = MagicMock()
    mock_ledger.get_entries_for_evidence.return_value = [
        LedgerEntry(
            id=1,
            evidence_id="EV-SEC-1",
            action="INGEST",
            actor="agent",
            sha256="aa" * 32,
            entry_hash="eh1",
        )
    ]
    mock_ledger.verify_ledger_integrity.return_value = ChainVerificationResult(
        is_valid=True, total_entries=1
    )

    mock_storage = MagicMock()
    mock_storage.bucket = test_settings.minio_bucket
    mock_storage.put_manifest.side_effect = (
        lambda m_id,
        content: f"minio://{test_settings.minio_bucket}/manifests/{m_id}.json"
    )

    gen = ManifestGenerator(
        settings=test_settings,
        custody_ledger=mock_ledger,
        storage_client=mock_storage,
    )

    # Attacker signs an HMAC manifest using the public key string as secret key
    attacker_manifest = gen.generate_manifest(
        evidence_ids=["EV-SEC-1"],
        signature_algorithm="HMAC-SHA256",
        signing_key=pub_hex,
    )

    # When verifier verifies with is_public_key=True (as from API ?public_key=...), it must be rejected!
    assert (
        gen.verify_manifest(attacker_manifest, key=pub_hex, is_public_key=True) is False
    )


# --- 2. Artifact Verification After Manifest EXPORT ---


def test_artifact_verification_succeeds_after_manifest_export(
    test_settings: Settings,
) -> None:
    """Verifies that ArtifactVerifier resolves the artifact's actual SHA256 even after multiple EXPORT entries."""
    mock_storage = MagicMock(spec=MinioClient)
    artifact_content = b"pristine-forensic-evidence-bytes"
    artifact_raw_sha = hashlib.sha256(artifact_content).hexdigest()
    mock_storage.get_object.return_value = artifact_content

    # Simulate evidence with INGEST, VERIFY, and multiple EXPORT actions
    mock_ledger = MagicMock()
    mock_ledger.get_entries_for_evidence.return_value = [
        LedgerEntry(
            id=1,
            evidence_id="EV-TEST-CHAIN",
            action="INGEST",
            actor="investigator",
            sha256=artifact_raw_sha,
            entry_hash="eh1",
        ),
        LedgerEntry(
            id=2,
            evidence_id="EV-TEST-CHAIN",
            action="EXPORT",
            actor="investigator",
            sha256="manifest_hash_different_from_artifact",
            entry_hash="eh2",
        ),
        LedgerEntry(
            id=3,
            evidence_id="EV-TEST-CHAIN",
            action="EXPORT",
            actor="investigator",
            sha256="second_manifest_hash",
            entry_hash="eh3",
        ),
    ]

    verifier = ArtifactVerifier(storage_client=mock_storage, custody_ledger=mock_ledger)
    result = verifier.verify_artifact("EV-TEST-CHAIN", actor="auditor")

    # Verifier must look up the artifact's INGEST hash, NOT the last EXPORT entry hash!
    mock_storage.get_object.assert_called_with("EV-TEST-CHAIN", artifact_raw_sha)
    assert result.status == VerificationStatus.MATCH
    assert result.match is True
    assert result.stored_sha256 == artifact_raw_sha


# --- 3. IP Spoofing Prevention on Developer Endpoints ---


def test_ip_spoofing_via_x_forwarded_for_blocked(
    test_settings: Settings,
) -> None:
    """Verifies that remote client connecting cannot bypass localhost restriction by spoofing X-Forwarded-For."""
    mock_request = MagicMock()
    mock_request.client.host = "198.51.100.42"  # Remote public IP
    mock_request.headers = {"X-Forwarded-For": "127.0.0.1"}  # Spoofed loopback header
    mock_request.url.path = "/graph/export"

    with pytest.raises(HTTPException) as exc_info:
        _guard_dev_endpoint(mock_request, test_settings)

    assert exc_info.value.status_code == 403


# --- 4. Mutable storage_uri Tampering Defense ---


def test_manifest_storage_uri_tampering_rejected(
    test_settings: Settings,
) -> None:
    """Verifies that modifying storage_uri to point to external or malicious URI fails verification."""
    mock_ledger = MagicMock()
    mock_ledger.get_entries_for_evidence.return_value = [
        LedgerEntry(
            id=1,
            evidence_id="EV-SEC-2",
            action="INGEST",
            actor="agent",
            sha256="bb" * 32,
            entry_hash="eh1",
        )
    ]
    mock_ledger.verify_ledger_integrity.return_value = ChainVerificationResult(
        is_valid=True, total_entries=1
    )
    mock_storage = MagicMock()
    mock_storage.bucket = test_settings.minio_bucket
    mock_storage.put_manifest.side_effect = (
        lambda m_id,
        content: f"minio://{test_settings.minio_bucket}/manifests/{m_id}.json"
    )

    gen = ManifestGenerator(
        settings=test_settings,
        custody_ledger=mock_ledger,
        storage_client=mock_storage,
    )
    manifest = gen.generate_manifest(evidence_ids=["EV-SEC-2"])
    assert gen.verify_manifest(manifest) is True

    # Tamper with storage_uri to point to external adversary server
    m_tampered = manifest.model_copy(
        update={"storage_uri": "https://attacker.com/malicious_manifest.json"}
    )
    assert gen.verify_manifest(m_tampered) is False

    # Tamper with storage_uri to point to different bucket
    m_tampered_bucket = manifest.model_copy(
        update={
            "storage_uri": f"minio://attacker-bucket/manifests/{manifest.manifest_id}.json"
        }
    )
    assert gen.verify_manifest(m_tampered_bucket) is False


# --- 5. Request Payload Constraints Defense ---


def test_create_manifest_payload_limits_enforced() -> None:
    """Verifies that oversized fields in CreateManifestRequest are rejected with 422 Unprocessable Entity."""
    with TestClient(app) as client:
        # Huge legal_declaration > 10,000 chars
        oversized_declaration = "A" * 10001
        r1 = client.post(
            "/manifests",
            json={
                "evidence_ids": ["EV-1"],
                "legal_declaration": oversized_declaration,
            },
        )
        assert r1.status_code == 422

        # Too many evidence_ids > 100
        too_many_ids = [f"EV-{i}" for i in range(101)]
        r2 = client.post("/manifests", json={"evidence_ids": too_many_ids})
        assert r2.status_code == 422

        # Oversized generator_identity > 256 chars
        r3 = client.post(
            "/manifests",
            json={
                "evidence_ids": ["EV-1"],
                "generator_identity": "O" * 257,
            },
        )
        assert r3.status_code == 422


# --- 6. Unicode NFC vs NFD Normalization Stability ---


def test_unicode_normalization_canonicalization_stability() -> None:
    """Verifies that Unicode strings in NFD vs NFC forms produce identical canonical serialization."""
    s_nfd = "Cafe\u0301"  # Decomposed (macOS style)
    s_nfc = "Caf\u00e9"  # Composed (Linux/Windows style)

    data_nfd = {"investigator": s_nfd, "case": "CYBER-01"}
    data_nfc = {"investigator": s_nfc, "case": "CYBER-01"}

    json_nfd = canonical_serialize(data_nfd)
    json_nfc = canonical_serialize(data_nfc)

    assert json_nfd == json_nfc
    assert "Café" in json_nfd
