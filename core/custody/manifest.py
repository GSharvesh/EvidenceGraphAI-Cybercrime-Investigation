"""Indian Evidence Act Section 65B / Bharatiya Sakshya Adhiniyam Section 63 compliant Evidence Manifest generator and digital signature verifier."""

import hashlib
import hmac
import uuid
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel

from core.config.settings import Settings, get_settings
from core.custody.chain import canonical_serialize
from core.custody.exceptions import ManifestGenerationError
from core.custody.ledger import CustodyLedger, LedgerEntry
from core.logging.logger import get_logger
from core.storage.minio_client import MinioClient

logger = get_logger("core.custody.manifest")

LEGAL_FRAMEWORK_BSA_2023 = "Section 63 Bharatiya Sakshya Adhiniyam, 2023 / BNSS 2023"
LEGAL_DECLARATION_BSA_2023 = (
    "CERTIFICATE UNDER SECTION 63 OF THE BHARATIYA SAKSHYA ADHINIYAM, 2023 (BSA) "
    "READ WITH SECTION 105 OF THE BHARATIYA NAGARIK SURAKSHA SANHITA, 2023 (BNSS): "
    "I hereby certify that the electronic records detailed in this manifest were produced by computer systems "
    "operating lawfully and properly during the period over which the evidence was collected. The data was "
    "ingested in the ordinary course of investigative activities, stored in an immutable, tamper-evident object "
    "repository, and tracked via a cryptographic hash-chained ledger. The cryptographic SHA256 hashes herein "
    "confirm the mathematical integrity and unaltered state of the source artifacts."
)

LEGAL_FRAMEWORK_IEA_1872 = "Section 65B Indian Evidence Act, 1872 / BNSS 2023"
LEGAL_DECLARATION_IEA_1872 = (
    "CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT, 1872: "
    "I hereby certify that the electronic records detailed in this manifest were produced by computer systems "
    "operating lawfully and properly during the period over which the evidence was collected. The data was "
    "ingested in the ordinary course of investigative activities, stored in an immutable, tamper-evident object "
    "repository, and tracked via a cryptographic hash-chained ledger. The cryptographic SHA256 hashes herein "
    "confirm the mathematical integrity and unaltered state of the source artifacts."
)

# Preserved default for backward compatibility
SECTION_65B_LEGAL_DECLARATION = LEGAL_DECLARATION_IEA_1872


def generate_ed25519_keypair() -> tuple[str, str]:
    """Generates a new Ed25519 private/public keypair as 64-character hex strings.

    Returns:
        tuple of (private_key_hex, public_key_hex).
    """
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = pub.public_bytes_raw()
    return priv_bytes.hex(), pub_bytes.hex()


def derive_ed25519_public_key(private_key_hex_or_bytes: str | bytes) -> str:
    """Derives the 64-character hex public key from a 32-byte Ed25519 private key.

    Args:
        private_key_hex_or_bytes: Hex-encoded string (64 chars) or raw 32 bytes.

    Returns:
        Hex-encoded 32-byte public key string.
    """
    if isinstance(private_key_hex_or_bytes, str):
        priv_bytes = bytes.fromhex(private_key_hex_or_bytes)
    else:
        priv_bytes = private_key_hex_or_bytes
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    return priv.public_key().public_bytes_raw().hex()


def sign_ed25519(
    payload_bytes: bytes,
    private_key_input: str | bytes | ed25519.Ed25519PrivateKey,
) -> str:
    """Signs bytes using Ed25519 and returns the 128-character hex-encoded signature.

    Args:
        payload_bytes: Raw bytes to sign.
        private_key_input: Hex string, raw bytes, or Ed25519PrivateKey instance.

    Returns:
        Hex-encoded signature string.
    """
    if isinstance(private_key_input, ed25519.Ed25519PrivateKey):
        priv = private_key_input
    elif isinstance(private_key_input, str):
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(private_key_input)
        )
    elif isinstance(private_key_input, bytes):
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_input)
    else:
        raise ValueError(f"Unsupported private key format: {type(private_key_input)}")
    sig = priv.sign(payload_bytes)
    return sig.hex()


def verify_ed25519(
    payload_bytes: bytes,
    signature_hex: str,
    public_key_input: str | bytes | ed25519.Ed25519PublicKey,
) -> bool:
    """Verifies an Ed25519 hex signature against payload bytes.

    Args:
        payload_bytes: Raw bytes that were signed.
        signature_hex: Hex-encoded signature string (128 chars).
        public_key_input: Hex string, raw bytes, or Ed25519PublicKey instance.

    Returns:
        True if signature is authentic; False otherwise.
    """
    try:
        if isinstance(public_key_input, ed25519.Ed25519PublicKey):
            pub = public_key_input
        elif isinstance(public_key_input, str):
            pub = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(public_key_input)
            )
        elif isinstance(public_key_input, bytes):
            pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_input)
        else:
            return False

        sig_bytes = bytes.fromhex(signature_hex)
        pub.verify(sig_bytes, payload_bytes)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class EvidenceItemSummary(BaseModel):
    """Forensic summary of an individual evidence artifact in the manifest."""

    evidence_id: str
    original_filename: str
    sha256: str
    artifact_type: str
    storage_path: str
    ingest_timestamp: str
    actor: str
    anonymized: bool = False
    dpdp_anonymization: dict[str, Any] | None = None
    chain_entry_count: int = 0


class EvidenceManifest(BaseModel):
    """Complete Section 65B / Section 63 Evidence Manifest document.

    Note: Cryptographic verification confirms mathematical integrity and provenance of the
    electronic artifact; statutory admissibility in court is a legal determination.
    """

    manifest_id: str
    generated_at: str
    generator_identity: str
    legal_framework: str = "Section 65B Indian Evidence Act / BNSS 2023"
    legal_declaration: str = SECTION_65B_LEGAL_DECLARATION
    evidence_count: int
    evidence_items: list[EvidenceItemSummary]
    chain_of_custody: list[dict[str, Any]]
    ledger_integrity_status: dict[str, Any]
    signature_algorithm: str = "HMAC-SHA256"
    digital_signature: str = ""
    storage_uri: str | None = None


class ManifestGenerator:
    """Generates, signs, verifies, and archives Section 65B / Section 63 Evidence Manifests."""

    def __init__(
        self,
        settings: Settings | None = None,
        custody_ledger: CustodyLedger | None = None,
        storage_client: MinioClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.ledger = custody_ledger or CustodyLedger()
        self.storage = storage_client or MinioClient(settings=self.settings)

    def _sign_manifest_content(
        self,
        manifest_dict: dict[str, Any],
        algorithm: str = "HMAC-SHA256",
        key: str | bytes | None = None,
    ) -> str:
        """Computes digital signature over canonicalized manifest dictionary excluding signature and storage fields.

        Args:
            manifest_dict: Manifest dictionary to sign.
            algorithm: 'HMAC-SHA256' or 'Ed25519'.
            key: Signing key (for HMAC: secret key; for Ed25519: 32-byte private key hex/bytes).
                 If None, retrieved from settings.

        Returns:
            Hex-encoded signature string.

        Raises:
            ManifestGenerationError: If algorithm is unsupported or required key is missing/invalid.
        """
        sign_payload = {
            k: v
            for k, v in manifest_dict.items()
            if k not in ("digital_signature", "storage_uri")
        }
        canonical = canonical_serialize(sign_payload)
        payload_bytes = canonical.encode("utf-8")

        algo_upper = algorithm.upper()
        if algo_upper == "HMAC-SHA256":
            secret_key = (
                key
                if isinstance(key, bytes)
                else (key or self.settings.manifest_signing_key).encode("utf-8")
            )
            return hmac.new(secret_key, payload_bytes, hashlib.sha256).hexdigest()
        elif algo_upper == "ED25519":
            priv_key = key or self.settings.manifest_signing_private_key
            if not priv_key:
                raise ManifestGenerationError(
                    "Ed25519 signing requires MANIFEST_SIGNING_PRIVATE_KEY or an explicit private_key"
                )
            try:
                return sign_ed25519(payload_bytes, priv_key)
            except Exception as exc:
                raise ManifestGenerationError(
                    f"Failed to sign manifest with Ed25519: {exc}"
                ) from exc
        else:
            raise ManifestGenerationError(
                f"Unsupported manifest signing algorithm: '{algorithm}'. Supported algorithms: HMAC-SHA256, Ed25519"
            )

    def generate_manifest(
        self,
        evidence_ids: list[str],
        generator_identity: str | None = None,
        actor: str = "system",
        legal_framework: str | None = None,
        legal_declaration: str | None = None,
        signature_algorithm: str | None = None,
        signing_key: str | bytes | None = None,
    ) -> EvidenceManifest:
        """Generates a legally formatted Evidence Manifest for a list of evidence items.

        Args:
            evidence_ids: List of evidence artifact IDs.
            generator_identity: Certifying official or authority name.
            actor: Actor executing the generation.
            legal_framework: Optional statutory legal framework name (e.g. BSA 2023 / IEA 1872).
            legal_declaration: Optional custom statutory certificate declaration text.
            signature_algorithm: Optional signing algorithm ('HMAC-SHA256' or 'Ed25519').
            signing_key: Optional override signing key.

        Returns:
            EvidenceManifest model.

        Raises:
            ManifestGenerationError: If manifest creation or storage fails.
        """
        if not evidence_ids:
            raise ManifestGenerationError(
                "Cannot generate Evidence Manifest with an empty evidence list"
            )

        manifest_id = f"MANIFEST-{uuid.uuid4()}"
        gen_id = generator_identity or self.settings.manifest_generator_identity
        gen_timestamp = datetime.now(UTC).isoformat()
        algo = (
            signature_algorithm
            or self.settings.manifest_signing_algorithm
            or "HMAC-SHA256"
        )

        framework = (
            legal_framework
            or self.settings.manifest_default_legal_framework
            or LEGAL_FRAMEWORK_IEA_1872
        )
        if legal_declaration:
            declaration = legal_declaration
        elif self.settings.manifest_default_legal_declaration:
            declaration = self.settings.manifest_default_legal_declaration
        elif "bharatiya sakshya" in framework.lower() or "bsa" in framework.lower():
            declaration = LEGAL_DECLARATION_BSA_2023
        else:
            declaration = SECTION_65B_LEGAL_DECLARATION

        evidence_items: list[EvidenceItemSummary] = []
        all_custody_entries: list[dict[str, Any]] = []

        for ev_id in evidence_ids:
            entries: list[LedgerEntry] = self.ledger.get_entries_for_evidence(ev_id)
            if not entries:
                raise ManifestGenerationError(
                    f"Evidence ID '{ev_id}' has no chain of custody ledger records"
                )

            ingest_entry = next(
                (e for e in entries if e.action == "INGEST"), entries[0]
            )
            anon_entry = next((e for e in entries if e.action == "ANONYMIZE"), None)

            meta = ingest_entry.metadata or {}
            item = EvidenceItemSummary(
                evidence_id=ev_id,
                original_filename=meta.get("original_filename", "unknown"),
                sha256=ingest_entry.sha256,
                artifact_type=meta.get("detected_type", "UNKNOWN"),
                storage_path=f"minio://{self.settings.minio_bucket}/evidence/{ev_id}/{ingest_entry.sha256}",
                ingest_timestamp=ingest_entry.timestamp,
                actor=ingest_entry.actor,
                anonymized=anon_entry is not None,
                dpdp_anonymization=anon_entry.metadata if anon_entry else None,
                chain_entry_count=len(entries),
            )
            evidence_items.append(item)
            all_custody_entries.extend([e.model_dump() for e in entries])

        # Global ledger integrity verification
        chain_res = self.ledger.verify_ledger_integrity()
        integrity_summary = {
            "is_valid": chain_res.is_valid,
            "total_entries": chain_res.total_entries,
            "message": chain_res.message,
        }

        # Build raw dict
        raw_manifest = {
            "manifest_id": manifest_id,
            "generated_at": gen_timestamp,
            "generator_identity": gen_id,
            "legal_framework": framework,
            "legal_declaration": declaration,
            "evidence_count": len(evidence_items),
            "evidence_items": [item.model_dump() for item in evidence_items],
            "chain_of_custody": all_custody_entries,
            "ledger_integrity_status": integrity_summary,
            "signature_algorithm": algo,
        }

        # Compute digital signature
        digital_signature = self._sign_manifest_content(
            raw_manifest, algorithm=algo, key=signing_key
        )
        raw_manifest["digital_signature"] = digital_signature

        # Store manifest in MinIO
        manifest_json_str = canonical_serialize(raw_manifest)
        storage_uri = ""
        try:
            storage_uri = self.storage.put_manifest(manifest_id, manifest_json_str)
            raw_manifest["storage_uri"] = storage_uri
        except Exception as exc:
            logger.warning("Could not persist manifest to storage", error=str(exc))

        # Record EXPORT entry in ledger for each evidence item
        manifest_sha = hashlib.sha256(manifest_json_str.encode("utf-8")).hexdigest()
        for ev_id in evidence_ids:
            item_match = next(
                (item for item in evidence_items if item.evidence_id == ev_id),
                None,
            )
            ev_sha = item_match.sha256 if item_match else manifest_sha
            try:
                self.ledger.append_entry(
                    evidence_id=ev_id,
                    action="EXPORT",
                    actor=actor,
                    sha256=ev_sha,
                    metadata={
                        "manifest_id": manifest_id,
                        "manifest_sha256": manifest_sha,
                        "generator": gen_id,
                    },
                    signature=digital_signature,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to record EXPORT entry in ledger",
                    evidence_id=ev_id,
                    error=str(exc),
                )

        logger.info(
            "Generated Evidence Manifest",
            manifest_id=manifest_id,
            framework=framework,
            algorithm=algo,
            count=len(evidence_items),
        )

        return EvidenceManifest(
            manifest_id=manifest_id,
            generated_at=gen_timestamp,
            generator_identity=gen_id,
            legal_framework=framework,
            legal_declaration=declaration,
            evidence_count=len(evidence_items),
            evidence_items=evidence_items,
            chain_of_custody=all_custody_entries,
            ledger_integrity_status=integrity_summary,
            signature_algorithm=algo,
            digital_signature=digital_signature,
            storage_uri=storage_uri,
        )

    def verify_manifest(
        self,
        manifest: dict[str, Any] | EvidenceManifest,
        key: str | bytes | None = None,
        is_public_key: bool = False,
    ) -> bool:
        """Verifies the digital signature and authenticity of an Evidence Manifest.

        Args:
            manifest: EvidenceManifest model or manifest dictionary.
            key: Optional verification key:
                 - For HMAC-SHA256: secret HMAC key (if None, uses settings.manifest_signing_key).
                 - For Ed25519: public key hex/bytes (if None, uses settings.manifest_signing_public_key
                   or derives from settings.manifest_signing_private_key).
            is_public_key: If True, indicates the key parameter is an asymmetric public key and
                 must reject HMAC-SHA256 manifests to prevent algorithm confusion/downgrade attacks.

        Returns:
            True if digital signature is valid and authentic; False otherwise.
        """
        manifest_dict = (
            manifest.model_dump()
            if isinstance(manifest, EvidenceManifest)
            else dict(manifest)
        )
        existing_sig = manifest_dict.get("digital_signature", "")
        if not existing_sig or not isinstance(existing_sig, str):
            return False

        algo = manifest_dict.get("signature_algorithm", "HMAC-SHA256")
        algo_upper = algo.upper() if isinstance(algo, str) else ""

        # Reject algorithm confusion: an untrusted public key cannot be used as a symmetric HMAC key
        if is_public_key and algo_upper != "ED25519":
            logger.warning(
                "Rejected algorithm confusion attempt: public key supplied for symmetric manifest verification",
                algorithm=algo,
            )
            return False

        # Validate storage_uri if present to prevent redirect/spoofing of evidence storage location
        manifest_id = manifest_dict.get("manifest_id", "")
        storage_uri = manifest_dict.get("storage_uri")
        if storage_uri:
            expected_suffix = f"/manifests/{manifest_id}.json"
            valid_buckets = {self.settings.minio_bucket}
            if hasattr(self, "storage") and hasattr(self.storage, "bucket"):
                valid_buckets.add(self.storage.bucket)

            is_valid_uri = (
                isinstance(storage_uri, str)
                and storage_uri.startswith("minio://")
                and storage_uri.endswith(expected_suffix)
                and any(
                    storage_uri == f"minio://{b}{expected_suffix}"
                    for b in valid_buckets
                )
            )
            if not is_valid_uri:
                logger.warning(
                    "Storage URI tamper detected in manifest",
                    actual=storage_uri,
                    valid_buckets=list(valid_buckets),
                )
                return False

        sign_payload = {
            k: v
            for k, v in manifest_dict.items()
            if k not in ("digital_signature", "storage_uri")
        }
        canonical = canonical_serialize(sign_payload)
        payload_bytes = canonical.encode("utf-8")

        if algo_upper == "HMAC-SHA256":
            secret_key = (
                key
                if isinstance(key, bytes)
                else (key or self.settings.manifest_signing_key).encode("utf-8")
            )
            computed_sig = hmac.new(
                secret_key, payload_bytes, hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(
                existing_sig.strip().lower(), computed_sig.lower()
            )

        elif algo_upper == "ED25519":
            pub_key: str | bytes | None = (
                key or self.settings.manifest_signing_public_key
            )
            if not pub_key and self.settings.manifest_signing_private_key:
                try:
                    pub_key = derive_ed25519_public_key(
                        self.settings.manifest_signing_private_key
                    )
                except Exception:
                    pub_key = None
            if not pub_key:
                logger.warning(
                    "No Ed25519 public key configured or provided for manifest verification"
                )
                return False

            return verify_ed25519(payload_bytes, existing_sig.strip(), pub_key)

        else:
            logger.warning("Unsupported manifest signature algorithm", algorithm=algo)
            return False
