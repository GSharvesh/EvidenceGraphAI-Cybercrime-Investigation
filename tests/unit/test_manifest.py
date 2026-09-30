"""Unit tests for Section 65B / Section 63 Evidence Manifest generator and verifier (HMAC-SHA256 & Ed25519)."""

from unittest.mock import MagicMock

import pytest

from core.config.settings import Settings
from core.custody.chain import ChainVerificationResult, LedgerEntry
from core.custody.exceptions import ManifestGenerationError
from core.custody.ledger import CustodyLedger
from core.custody.manifest import (
    ManifestGenerator,
    derive_ed25519_public_key,
    generate_ed25519_keypair,
    sign_ed25519,
    verify_ed25519,
)
from core.storage.minio_client import MinioClient


@pytest.fixture
def mock_storage() -> MagicMock:
    storage = MagicMock(spec=MinioClient)
    storage.bucket = "test-bucket"
    storage.put_manifest.side_effect = (
        lambda m_id, content: f"minio://test-bucket/manifests/{m_id}.json"
    )
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
            metadata={
                "original_filename": "evidence.pcap",
                "detected_type": "PCAP",
            },
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


# --- HMAC-SHA256 Tests ---


def test_generate_manifest_success(
    manifest_gen: ManifestGenerator,
    mock_storage: MagicMock,
    mock_ledger: MagicMock,
) -> None:
    """Verifies that generate_manifest produces Section 65B declaration, items, chain, and signature."""
    manifest = manifest_gen.generate_manifest(
        evidence_ids=["EV-1"],
        generator_identity="Chief Forensic Examiner",
        actor="examiner_01",
    )

    assert manifest.manifest_id.startswith("MANIFEST-")
    assert manifest.evidence_count == 1
    assert len(manifest.evidence_items) == 1
    assert manifest.evidence_items[0].evidence_id == "EV-1"
    assert "SECTION 65B" in manifest.legal_declaration
    assert manifest.signature_algorithm == "HMAC-SHA256"
    assert manifest.digital_signature != ""
    assert manifest.ledger_integrity_status["is_valid"] is True
    mock_storage.put_manifest.assert_called_once()
    mock_ledger.append_entry.assert_called_once()


def test_verify_manifest_signature(manifest_gen: ManifestGenerator) -> None:
    """Verifies HMAC signature verification passes on untouched manifest and fails on altered manifest."""
    manifest = manifest_gen.generate_manifest(evidence_ids=["EV-1"])
    assert manifest_gen.verify_manifest(manifest) is True

    manifest_tampered = manifest.model_copy(update={"generator_identity": "Impostor"})
    assert manifest_gen.verify_manifest(manifest_tampered) is False


def test_verify_manifest_tampered_evidence_item(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies that altering SHA-256 or filename in evidence items causes verification to fail."""
    manifest = manifest_gen.generate_manifest(evidence_ids=["EV-1"])
    assert manifest_gen.verify_manifest(manifest) is True

    tampered_items = [
        item.model_copy(
            update={
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            }
        )
        for item in manifest.evidence_items
    ]
    manifest_tampered = manifest.model_copy(update={"evidence_items": tampered_items})
    assert manifest_gen.verify_manifest(manifest_tampered) is False


def test_verify_manifest_tampered_timestamp(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies that altering generated_at timestamp causes signature verification to fail."""
    manifest = manifest_gen.generate_manifest(evidence_ids=["EV-1"])
    manifest_tampered = manifest.model_copy(
        update={"generated_at": "1999-01-01T00:00:00+00:00"}
    )
    assert manifest_gen.verify_manifest(manifest_tampered) is False


def test_verify_manifest_tampered_chain(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies that altering custody chain entries in the manifest causes verification to fail."""
    manifest = manifest_gen.generate_manifest(evidence_ids=["EV-1"])
    tampered_chain = list(manifest.chain_of_custody)
    tampered_chain.append({"action": "MALICIOUS_INJECTION", "id": 999})
    manifest_tampered = manifest.model_copy(update={"chain_of_custody": tampered_chain})
    assert manifest_gen.verify_manifest(manifest_tampered) is False


def test_verify_manifest_corrupted_signature(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies that corrupting or truncating the signature causes verification to fail."""
    manifest = manifest_gen.generate_manifest(evidence_ids=["EV-1"])
    manifest_tampered = manifest.model_copy(
        update={"digital_signature": "deadbeef" * 8}
    )
    assert manifest_gen.verify_manifest(manifest_tampered) is False

    manifest_empty_sig = manifest.model_copy(update={"digital_signature": ""})
    assert manifest_gen.verify_manifest(manifest_empty_sig) is False


def test_verify_manifest_wrong_key(manifest_gen: ManifestGenerator) -> None:
    """Verifies that verification fails when checked with a different secret key."""
    manifest = manifest_gen.generate_manifest(evidence_ids=["EV-1"])
    assert (
        manifest_gen.verify_manifest(manifest, key="wrong-secret-key-1234567890")
        is False
    )


def test_generate_manifest_bsa_2023_framework(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies generating a manifest under current Bharatiya Sakshya Adhiniyam, 2023 (BSA)."""
    manifest = manifest_gen.generate_manifest(
        evidence_ids=["EV-1"],
        generator_identity="Cyber Forensic Cell",
        legal_framework="Section 63 Bharatiya Sakshya Adhiniyam, 2023 / BNSS 2023",
    )
    assert (
        "SECTION 63 OF THE BHARATIYA SAKSHYA ADHINIYAM, 2023"
        in manifest.legal_declaration
    )
    assert (
        manifest.legal_framework
        == "Section 63 Bharatiya Sakshya Adhiniyam, 2023 / BNSS 2023"
    )
    assert manifest_gen.verify_manifest(manifest) is True


def test_generate_manifest_legacy_iea_framework(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies generating a manifest under legacy Section 65B Indian Evidence Act, 1872."""
    manifest = manifest_gen.generate_manifest(
        evidence_ids=["EV-1"],
        generator_identity="Digital Evidence Unit",
        legal_framework="Section 65B Indian Evidence Act, 1872",
    )
    assert "SECTION 65B OF THE INDIAN EVIDENCE ACT, 1872" in manifest.legal_declaration
    assert manifest.legal_framework == "Section 65B Indian Evidence Act, 1872"
    assert manifest_gen.verify_manifest(manifest) is True


def test_generate_manifest_custom_declaration(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies generating a manifest with a fully customized legal declaration."""
    custom_decl = "CUSTOM AFFIDAVIT OF DIGITAL AUTHENTICITY UNDER STATUTORY PROVISIONS"
    custom_fw = "Custom Forensic Authority Framework v1.0"
    manifest = manifest_gen.generate_manifest(
        evidence_ids=["EV-1"],
        generator_identity="State Special Investigation Team",
        legal_framework=custom_fw,
        legal_declaration=custom_decl,
    )
    assert manifest.legal_framework == custom_fw
    assert manifest.legal_declaration == custom_decl
    assert manifest_gen.verify_manifest(manifest) is True


def test_verify_manifest_tampered_legal_framework(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies that altering legal_framework invalidates the digital signature."""
    manifest = manifest_gen.generate_manifest(evidence_ids=["EV-1"])
    assert manifest_gen.verify_manifest(manifest) is True

    manifest_tampered = manifest.model_copy(
        update={"legal_framework": "Tampered Unofficial Legal Code"}
    )
    assert manifest_gen.verify_manifest(manifest_tampered) is False


def test_verify_manifest_tampered_legal_declaration(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies that altering legal_declaration text invalidates the digital signature."""
    manifest = manifest_gen.generate_manifest(evidence_ids=["EV-1"])
    assert manifest_gen.verify_manifest(manifest) is True

    manifest_tampered = manifest.model_copy(
        update={"legal_declaration": "Altered and fraudulent certificate text"}
    )
    assert manifest_gen.verify_manifest(manifest_tampered) is False


def test_generate_manifest_empty_list_raises(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies empty evidence list raises ManifestGenerationError."""
    with pytest.raises(ManifestGenerationError):
        manifest_gen.generate_manifest(evidence_ids=[])


# --- Ed25519 Asymmetric Signing Tests ---


def test_ed25519_keypair_generation_and_derivation() -> None:
    """Verifies Ed25519 key generation and public key derivation."""
    priv_hex, pub_hex = generate_ed25519_keypair()
    assert len(priv_hex) == 64
    assert len(pub_hex) == 64
    assert derive_ed25519_public_key(priv_hex) == pub_hex
    assert derive_ed25519_public_key(bytes.fromhex(priv_hex)) == pub_hex


def test_ed25519_sign_and_verify_low_level() -> None:
    """Verifies low-level sign_ed25519 and verify_ed25519 primitives."""
    priv_hex, pub_hex = generate_ed25519_keypair()
    data = b"forensic-evidence-canonical-bytes"
    sig_hex = sign_ed25519(data, priv_hex)
    assert len(sig_hex) == 128

    # Valid verify
    assert verify_ed25519(data, sig_hex, pub_hex) is True
    assert verify_ed25519(data, sig_hex, bytes.fromhex(pub_hex)) is True

    # Tampered data
    assert verify_ed25519(b"altered-bytes", sig_hex, pub_hex) is False

    # Wrong public key
    _, other_pub = generate_ed25519_keypair()
    assert verify_ed25519(data, sig_hex, other_pub) is False

    # Corrupted signature
    assert verify_ed25519(data, "00" * 64, pub_hex) is False
    assert verify_ed25519(data, "invalid-hex", pub_hex) is False
    assert verify_ed25519(data, "", pub_hex) is False


def test_generate_and_verify_manifest_ed25519_explicit_keys(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies generating an Ed25519 manifest with explicit private key and verifying with public key."""
    priv_hex, pub_hex = generate_ed25519_keypair()
    manifest = manifest_gen.generate_manifest(
        evidence_ids=["EV-1"],
        generator_identity="Independent Forensic Examiner",
        signature_algorithm="Ed25519",
        signing_key=priv_hex,
    )

    assert manifest.signature_algorithm == "Ed25519"
    assert len(manifest.digital_signature) == 128
    assert manifest_gen.verify_manifest(manifest, key=pub_hex) is True


def test_generate_and_verify_manifest_ed25519_settings_keys(
    mock_ledger: MagicMock, mock_storage: MagicMock
) -> None:
    """Verifies generating and verifying Ed25519 manifest using settings configuration."""
    priv_hex, pub_hex = generate_ed25519_keypair()
    settings = Settings(
        manifest_signing_algorithm="Ed25519",
        manifest_signing_private_key=priv_hex,
        manifest_signing_public_key=pub_hex,
    )
    gen = ManifestGenerator(
        settings=settings,
        custody_ledger=mock_ledger,
        storage_client=mock_storage,
    )

    manifest = gen.generate_manifest(evidence_ids=["EV-1"])
    assert manifest.signature_algorithm == "Ed25519"
    assert gen.verify_manifest(manifest) is True


def test_verify_manifest_ed25519_tampered_payload_fields(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies that tampering with any field in an Ed25519 manifest causes verification to fail."""
    priv_hex, pub_hex = generate_ed25519_keypair()
    manifest = manifest_gen.generate_manifest(
        evidence_ids=["EV-1"],
        signature_algorithm="Ed25519",
        signing_key=priv_hex,
    )
    assert manifest_gen.verify_manifest(manifest, key=pub_hex) is True

    # Tampered generator identity
    m1 = manifest.model_copy(update={"generator_identity": "Fake Officer"})
    assert manifest_gen.verify_manifest(m1, key=pub_hex) is False

    # Tampered timestamp
    m2 = manifest.model_copy(update={"generated_at": "2020-01-01T00:00:00+00:00"})
    assert manifest_gen.verify_manifest(m2, key=pub_hex) is False

    # Tampered legal framework
    m3 = manifest.model_copy(update={"legal_framework": "Altered Act"})
    assert manifest_gen.verify_manifest(m3, key=pub_hex) is False

    # Tampered legal declaration
    m4 = manifest.model_copy(update={"legal_declaration": "Tampered text"})
    assert manifest_gen.verify_manifest(m4, key=pub_hex) is False

    # Tampered evidence items
    tampered_items = [
        item.model_copy(update={"sha256": "1" * 64}) for item in manifest.evidence_items
    ]
    m5 = manifest.model_copy(update={"evidence_items": tampered_items})
    assert manifest_gen.verify_manifest(m5, key=pub_hex) is False

    # Tampered custody chain
    tampered_chain = list(manifest.chain_of_custody) + [{"injected": True}]
    m6 = manifest.model_copy(update={"chain_of_custody": tampered_chain})
    assert manifest_gen.verify_manifest(m6, key=pub_hex) is False

    # Tampered algorithm (switching algorithm field)
    m7 = manifest.model_copy(update={"signature_algorithm": "HMAC-SHA256"})
    assert manifest_gen.verify_manifest(m7, key=pub_hex) is False


def test_verify_manifest_ed25519_wrong_public_key(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies that an Ed25519 manifest fails verification when checked with a different public key."""
    priv_hex, _ = generate_ed25519_keypair()
    _, wrong_pub = generate_ed25519_keypair()
    manifest = manifest_gen.generate_manifest(
        evidence_ids=["EV-1"],
        signature_algorithm="Ed25519",
        signing_key=priv_hex,
    )
    assert manifest_gen.verify_manifest(manifest, key=wrong_pub) is False


def test_verify_manifest_ed25519_corrupted_signature(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies corrupted or invalid hex signatures fail gracefully for Ed25519."""
    priv_hex, pub_hex = generate_ed25519_keypair()
    manifest = manifest_gen.generate_manifest(
        evidence_ids=["EV-1"],
        signature_algorithm="Ed25519",
        signing_key=priv_hex,
    )

    m_corrupt = manifest.model_copy(
        update={"digital_signature": "0123456789abcdef" * 8}
    )
    assert manifest_gen.verify_manifest(m_corrupt, key=pub_hex) is False

    m_invalid_hex = manifest.model_copy(
        update={"digital_signature": "not-a-hex-string"}
    )
    assert manifest_gen.verify_manifest(m_invalid_hex, key=pub_hex) is False

    m_empty = manifest.model_copy(update={"digital_signature": ""})
    assert manifest_gen.verify_manifest(m_empty, key=pub_hex) is False


def test_generate_manifest_ed25519_missing_private_key_raises(
    mock_ledger: MagicMock, mock_storage: MagicMock
) -> None:
    """Verifies that requesting Ed25519 signing without configuring or passing a private key raises error."""
    settings = Settings(
        manifest_signing_algorithm="Ed25519",
        manifest_signing_private_key=None,
    )
    gen = ManifestGenerator(
        settings=settings,
        custody_ledger=mock_ledger,
        storage_client=mock_storage,
    )
    with pytest.raises(ManifestGenerationError, match="Ed25519 signing requires"):
        gen.generate_manifest(evidence_ids=["EV-1"])


def test_verify_manifest_ed25519_missing_public_key_returns_false(
    mock_ledger: MagicMock, mock_storage: MagicMock
) -> None:
    """Verifies that verifying an Ed25519 manifest without configured or provided public key returns False."""
    priv_hex, pub_hex = generate_ed25519_keypair()
    settings_no_key = Settings(
        manifest_signing_algorithm="HMAC-SHA256",
        manifest_signing_private_key=None,
        manifest_signing_public_key=None,
    )
    gen = ManifestGenerator(
        settings=settings_no_key,
        custody_ledger=mock_ledger,
        storage_client=mock_storage,
    )

    manifest = gen.generate_manifest(
        evidence_ids=["EV-1"],
        signature_algorithm="Ed25519",
        signing_key=priv_hex,
    )
    # Verification with no key supplied and none in settings returns False
    assert gen.verify_manifest(manifest, key=None) is False
    # Verification with explicit key returns True
    assert gen.verify_manifest(manifest, key=pub_hex) is True


def test_unsupported_algorithm_handling(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies unsupported signing algorithm raises on generation and returns False on verification."""
    with pytest.raises(
        ManifestGenerationError, match="Unsupported manifest signing algorithm"
    ):
        manifest_gen.generate_manifest(
            evidence_ids=["EV-1"],
            signature_algorithm="RSA-MD5",
        )

    manifest = manifest_gen.generate_manifest(evidence_ids=["EV-1"])
    m_unknown = manifest.model_copy(update={"signature_algorithm": "UNKNOWN"})
    assert manifest_gen.verify_manifest(m_unknown) is False


def test_private_key_not_exposed_in_manifest_model(
    manifest_gen: ManifestGenerator,
) -> None:
    """Verifies that private keys or internal secrets are never included in manifest model output."""
    priv_hex, _ = generate_ed25519_keypair()
    manifest = manifest_gen.generate_manifest(
        evidence_ids=["EV-1"],
        signature_algorithm="Ed25519",
        signing_key=priv_hex,
    )
    dump = manifest.model_dump()
    dump_str = str(dump)

    assert priv_hex not in dump_str
    assert "private_key" not in dump
    assert "secret_key" not in dump
    assert hasattr(manifest, "manifest_signing_key") is False
    assert hasattr(manifest, "manifest_signing_private_key") is False
