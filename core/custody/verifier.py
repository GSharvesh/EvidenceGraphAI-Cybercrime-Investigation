"""On-demand cryptographic hash verification service for forensic artifacts."""

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from core.custody.exceptions import ArtifactVerificationError
from core.custody.ledger import CustodyLedger
from core.ingestion.hasher import compute_sha256_bytes
from core.logging.logger import get_logger
from core.storage.exceptions import ObjectNotFoundError
from core.storage.minio_client import MinioClient

logger = get_logger("core.custody.verifier")


class VerificationStatus(str, Enum):
    """Status of artifact verification."""

    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NOT_FOUND = "NOT_FOUND"


class VerificationResult(BaseModel):
    """Outcome of on-demand artifact verification."""

    evidence_id: str
    status: VerificationStatus
    stored_sha256: str
    recomputed_sha256: str | None = None
    match: bool
    verified_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    ledger_entry_id: int | None = None
    message: str = "Verification completed"


class ArtifactVerifier:
    """Performs cryptographic recomputation and comparison of stored artifacts."""

    def __init__(
        self,
        storage_client: MinioClient | None = None,
        custody_ledger: CustodyLedger | None = None,
    ) -> None:
        self.storage = storage_client or MinioClient()
        self.ledger = custody_ledger or CustodyLedger()

    def verify_artifact(
        self,
        evidence_id: str,
        actor: str = "system",
    ) -> VerificationResult:
        """Fetches artifact from storage, recomputes SHA256, verifies against ledger, and records action.

        Args:
            evidence_id: Target evidence ID string.
            actor: Identity of verifier.

        Returns:
            VerificationResult.

        Raises:
            ArtifactVerificationError: If verification process encounters unexpected system failure.
        """
        # Find expected SHA256 from ledger records
        entries = self.ledger.get_entries_for_evidence(evidence_id)
        if not entries:
            logger.warning(
                "Evidence not found in custody ledger", evidence_id=evidence_id
            )
            return VerificationResult(
                evidence_id=evidence_id,
                status=VerificationStatus.NOT_FOUND,
                stored_sha256="",
                recomputed_sha256=None,
                match=False,
                message=f"No custody ledger entries found for evidence ID '{evidence_id}'",
            )

        # Get latest recorded artifact sha256
        expected_sha256 = entries[-1].sha256

        try:
            artifact_bytes = self.storage.get_object(evidence_id, expected_sha256)
        except ObjectNotFoundError:
            logger.warning(
                "Artifact missing in storage",
                evidence_id=evidence_id,
                sha256=expected_sha256,
            )
            return VerificationResult(
                evidence_id=evidence_id,
                status=VerificationStatus.NOT_FOUND,
                stored_sha256=expected_sha256,
                recomputed_sha256=None,
                match=False,
                message=f"Artifact object for '{evidence_id}' not found in MinIO storage",
            )
        except Exception as exc:
            raise ArtifactVerificationError(
                f"Failed to retrieve artifact from storage: {exc}"
            ) from exc

        # Recompute SHA256
        recomputed_sha256 = compute_sha256_bytes(artifact_bytes)
        is_match = recomputed_sha256.lower() == expected_sha256.lower()
        status = VerificationStatus.MATCH if is_match else VerificationStatus.MISMATCH

        # Record VERIFY entry in ledger
        meta = {
            "expected_sha256": expected_sha256,
            "recomputed_sha256": recomputed_sha256,
            "verification_status": status.value,
            "match": is_match,
        }

        entry_id: int | None = None
        try:
            verify_entry = self.ledger.append_entry(
                evidence_id=evidence_id,
                action="VERIFY",
                actor=actor,
                sha256=expected_sha256,
                metadata=meta,
            )
            entry_id = verify_entry.id
        except Exception as exc:
            logger.warning("Failed to record VERIFY entry in ledger", error=str(exc))

        msg = (
            "Cryptographic hash successfully verified: artifact is pristine and unaltered"
            if is_match
            else f"CRITICAL: Artifact hash mismatch detected! Expected '{expected_sha256}', found '{recomputed_sha256}'"
        )

        return VerificationResult(
            evidence_id=evidence_id,
            status=status,
            stored_sha256=expected_sha256,
            recomputed_sha256=recomputed_sha256,
            match=is_match,
            ledger_entry_id=entry_id,
            message=msg,
        )
