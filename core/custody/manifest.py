"""Indian Evidence Act Section 65B compliant Evidence Manifest generator and digital signature verifier."""

import hashlib
import hmac
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from core.config.settings import Settings, get_settings
from core.custody.chain import canonical_serialize
from core.custody.exceptions import ManifestGenerationError
from core.custody.ledger import CustodyLedger, LedgerEntry
from core.logging.logger import get_logger
from core.storage.minio_client import MinioClient

logger = get_logger("core.custody.manifest")

SECTION_65B_LEGAL_DECLARATION = (
    "CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT, 1872: "
    "I hereby certify that the electronic records detailed in this manifest were produced by computer systems "
    "operating lawfully and properly during the period over which the evidence was collected. The data was "
    "ingested in the ordinary course of investigative activities, stored in an immutable, tamper-evident object "
    "repository, and tracked via a cryptographic hash-chained ledger. The cryptographic SHA256 hashes herein "
    "confirm the mathematical integrity and unaltered state of the source artifacts."
)


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
    """Complete Section 65B Evidence Manifest document."""

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
    """Generates, signs, verifies, and archives Section 65B Evidence Manifests."""

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
        self, manifest_dict: dict[str, Any], key: str | None = None
    ) -> str:
        """Computes HMAC-SHA256 signature over canonicalized manifest dictionary excluding signature field."""
        sign_payload = {
            k: v
            for k, v in manifest_dict.items()
            if k not in ("digital_signature", "storage_uri")
        }
        canonical = canonical_serialize(sign_payload)
        secret_key = (key or self.settings.manifest_signing_key).encode("utf-8")
        return hmac.new(
            secret_key, canonical.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def generate_manifest(
        self,
        evidence_ids: list[str],
        generator_identity: str | None = None,
        actor: str = "system",
    ) -> EvidenceManifest:
        """Generates a complete Section 65B Evidence Manifest for a list of evidence items.

        Args:
            evidence_ids: List of evidence artifact IDs.
            generator_identity: Certifying official or authority name.
            actor: Actor executing the generation.

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
            "legal_framework": "Section 65B Indian Evidence Act / BNSS 2023",
            "legal_declaration": SECTION_65B_LEGAL_DECLARATION,
            "evidence_count": len(evidence_items),
            "evidence_items": [item.model_dump() for item in evidence_items],
            "chain_of_custody": all_custody_entries,
            "ledger_integrity_status": integrity_summary,
            "signature_algorithm": "HMAC-SHA256",
        }

        # Compute digital signature
        digital_signature = self._sign_manifest_content(raw_manifest)
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
            try:
                self.ledger.append_entry(
                    evidence_id=ev_id,
                    action="EXPORT",
                    actor=actor,
                    sha256=manifest_sha,
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
            "Generated Section 65B Evidence Manifest",
            manifest_id=manifest_id,
            count=len(evidence_items),
        )

        return EvidenceManifest(
            manifest_id=manifest_id,
            generated_at=gen_timestamp,
            generator_identity=gen_id,
            legal_framework="Section 65B Indian Evidence Act / BNSS 2023",
            legal_declaration=SECTION_65B_LEGAL_DECLARATION,
            evidence_count=len(evidence_items),
            evidence_items=evidence_items,
            chain_of_custody=all_custody_entries,
            ledger_integrity_status=integrity_summary,
            signature_algorithm="HMAC-SHA256",
            digital_signature=digital_signature,
            storage_uri=storage_uri,
        )

    def verify_manifest(
        self,
        manifest: dict[str, Any] | EvidenceManifest,
        key: str | None = None,
    ) -> bool:
        """Verifies the digital signature and authenticity of an Evidence Manifest."""
        manifest_dict = (
            manifest.model_dump()
            if isinstance(manifest, EvidenceManifest)
            else dict(manifest)
        )
        existing_sig = manifest_dict.get("digital_signature", "")
        if not existing_sig:
            return False

        computed_sig = self._sign_manifest_content(manifest_dict, key=key)
        return hmac.compare_digest(existing_sig, computed_sig)
