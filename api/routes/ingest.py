"""Forensic artifact ingestion and evidence management API endpoints."""

import contextlib
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)
from pydantic import BaseModel

from api.dependencies import (
    get_artifact_ingestor,
    get_artifact_verifier,
    get_custody_ledger,
    get_manifest_generator,
    get_minio_client,
)
from core.custody.ledger import CustodyLedger
from core.custody.manifest import EvidenceManifest, ManifestGenerator
from core.custody.verifier import ArtifactVerifier, VerificationResult
from core.ingestion.exceptions import (
    DuplicateArtifactError,
    FileTooLargeError,
    InvalidFileError,
    UnsupportedFileTypeError,
)
from core.ingestion.ingestor import ArtifactIngestor, IngestResult
from core.logging.logger import get_logger
from core.privacy.anonymizer import AnonymizationMethod
from core.storage.minio_client import MinioClient

router = APIRouter(tags=["Ingestion & Evidence"])
logger = get_logger("api.routes.ingest")


class IngestStatsResponse(BaseModel):
    """Aggregate statistics for forensic artifact ingestion."""

    total_evidence_artifacts: int
    total_ledger_entries: int
    action_breakdown: dict[str, int]
    storage_bucket: str
    latest_ingest_timestamp: str | None


@router.post(
    "/ingest",
    response_model=IngestResult,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and ingest a raw forensic artifact",
)
async def ingest_artifact(
    file: UploadFile = File(..., description="Forensic artifact binary or text file"),
    actor: str = Form("system", description="Actor or agent performing the ingestion"),
    anonymize: bool | None = Form(
        None, description="Toggle DPDP Act PII anonymization"
    ),
    anonymize_method: str = Form(
        "MASK", description="Anonymization method (MASK, PSEUDONYMIZE, REDACT)"
    ),
    evidence_type_hint: str | None = Form(
        None, description="Optional evidence type hint"
    ),
    ingestor: ArtifactIngestor = Depends(get_artifact_ingestor),
) -> IngestResult:
    """Accepts heterogeneous forensic artifacts (PCAP, JSON, PE/ELF/APK, logs, certs),
    validates format, computes SHA256, stores in MinIO, creates EvidenceArtifact graph node,
    and appends to append-only custody ledger.
    """
    try:
        content = await file.read()
        filename = file.filename or "artifact.bin"

        try:
            method_enum = AnonymizationMethod(anonymize_method.upper())
        except ValueError:
            method_enum = AnonymizationMethod.MASK

        result = ingestor.ingest(
            data_or_stream_or_path=content,
            filename=filename,
            evidence_type_hint=evidence_type_hint,
            actor=actor,
            anonymize=anonymize,
            anonymize_method=method_enum,
        )
        return result

    except UnsupportedFileTypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except FileTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)
        ) from exc
    except InvalidFileError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except DuplicateArtifactError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    except Exception as exc:
        logger.error("Unhandled ingestion exception", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ingestion failed: {exc}",
        ) from exc


@router.get(
    "/evidence/{evidence_id}",
    summary="Get metadata and custody trail for an evidence artifact",
)
def get_evidence(
    evidence_id: str,
    ledger: CustodyLedger = Depends(get_custody_ledger),
    storage: MinioClient = Depends(get_minio_client),
) -> dict[str, Any]:
    """Retrieves artifact details, storage metadata, and complete chain of custody records."""
    entries = ledger.get_entries_for_evidence(evidence_id)
    if not entries:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found",
        )

    ingest_entry = next((e for e in entries if e.action == "INGEST"), entries[0])
    sha256 = ingest_entry.sha256

    storage_meta: dict[str, Any] = {}
    with contextlib.suppress(Exception):
        storage_meta = storage.get_object_metadata(evidence_id, sha256)

    return {
        "evidence_id": evidence_id,
        "sha256": sha256,
        "artifact_type": ingest_entry.metadata.get("detected_type", "UNKNOWN"),
        "original_filename": ingest_entry.metadata.get("original_filename", "unknown"),
        "ingested_at": ingest_entry.timestamp,
        "actor": ingest_entry.actor,
        "storage_path": f"minio://{storage.bucket}/evidence/{evidence_id}/{sha256}",
        "storage_details": storage_meta,
        "custody_chain": [e.model_dump() for e in entries],
    }


@router.get(
    "/evidence/{evidence_id}/verify",
    response_model=VerificationResult,
    summary="Cryptographically verify artifact integrity against ledger",
)
def verify_evidence(
    evidence_id: str,
    actor: str = "system",
    verifier: ArtifactVerifier = Depends(get_artifact_verifier),
) -> VerificationResult:
    """Fetches artifact from storage, recomputes SHA256, compares with ledger, and logs VERIFY action."""
    result = verifier.verify_artifact(evidence_id, actor=actor)
    if result.status == "NOT_FOUND":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=result.message
        )
    return result


@router.get(
    "/evidence/{evidence_id}/manifest",
    response_model=EvidenceManifest,
    summary="Generate Section 65B Evidence Manifest for a specific evidence item",
)
def get_evidence_manifest(
    evidence_id: str,
    generator: ManifestGenerator = Depends(get_manifest_generator),
) -> EvidenceManifest:
    """Generates Section 65B Evidence Manifest for the given artifact."""
    try:
        return generator.generate_manifest(evidence_ids=[evidence_id])
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Manifest generation failed: {exc}",
        ) from exc


@router.get(
    "/ingest/stats",
    response_model=IngestStatsResponse,
    summary="Ingestion and custody statistics",
)
def get_ingest_stats(
    ledger: CustodyLedger = Depends(get_custody_ledger),
    storage: MinioClient = Depends(get_minio_client),
) -> IngestStatsResponse:
    """Returns total evidence items, ledger action counts, and storage metrics."""
    stats = ledger.get_ledger_stats()
    return IngestStatsResponse(
        total_evidence_artifacts=stats.get("total_evidence_items", 0),
        total_ledger_entries=stats.get("total_entries", 0),
        action_breakdown=stats.get("action_counts", {}),
        storage_bucket=storage.bucket,
        latest_ingest_timestamp=stats.get("latest_entry_timestamp"),
    )
