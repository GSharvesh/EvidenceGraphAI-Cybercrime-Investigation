"""Section 65B Evidence Manifest API endpoints."""

import json

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from api.dependencies import get_manifest_generator, get_minio_client
from core.custody.exceptions import ManifestGenerationError
from core.custody.manifest import EvidenceManifest, ManifestGenerator
from core.storage.minio_client import MinioClient

router = APIRouter(tags=["Evidence Manifests"])


class CreateManifestRequest(BaseModel):
    """Request payload for creating an Evidence Manifest."""

    evidence_ids: list[str] = Field(
        ..., min_length=1, description="List of evidence IDs to certify"
    )
    generator_identity: str | None = Field(
        None, description="Certifying officer or organization name"
    )
    actor: str = Field("system", description="Actor generating the manifest")


class ManifestVerificationResponse(BaseModel):
    """Result of digital signature verification on a manifest."""

    manifest_id: str
    is_valid: bool
    signature_algorithm: str
    message: str


@router.post(
    "/manifests",
    response_model=EvidenceManifest,
    status_code=status.HTTP_201_CREATED,
    summary="Generate and sign a Section 65B Evidence Manifest",
)
def create_manifest(
    payload: CreateManifestRequest,
    generator: ManifestGenerator = Depends(get_manifest_generator),
) -> EvidenceManifest:
    """Generates a legally formatted Section 65B manifest with cryptographic signatures,
    full chain of custody, and integrity proofs, and archives it in MinIO."""
    try:
        manifest = generator.generate_manifest(
            evidence_ids=payload.evidence_ids,
            generator_identity=payload.generator_identity,
            actor=payload.actor,
        )
        return manifest
    except ManifestGenerationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate manifest: {exc}",
        ) from exc


@router.get(
    "/manifests/{manifest_id}",
    response_model=EvidenceManifest,
    summary="Fetch an archived Evidence Manifest by ID",
)
def get_manifest_by_id(
    manifest_id: str,
    storage: MinioClient = Depends(get_minio_client),
) -> EvidenceManifest:
    """Retrieves an archived Section 65B Evidence Manifest JSON from MinIO."""
    try:
        data_bytes = storage.get_manifest(manifest_id)
        manifest_data = json.loads(data_bytes.decode("utf-8"))
        return EvidenceManifest(**manifest_data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Manifest '{manifest_id}' not found in storage: {exc}",
        ) from exc


@router.post(
    "/manifests/verify",
    response_model=ManifestVerificationResponse,
    summary="Verify digital signature and authenticity of an Evidence Manifest",
)
def verify_manifest_signature(
    manifest: EvidenceManifest,
    generator: ManifestGenerator = Depends(get_manifest_generator),
) -> ManifestVerificationResponse:
    """Verifies HMAC/Ed25519 signature of the provided Evidence Manifest document."""
    is_valid = generator.verify_manifest(manifest)
    return ManifestVerificationResponse(
        manifest_id=manifest.manifest_id,
        is_valid=is_valid,
        signature_algorithm=manifest.signature_algorithm,
        message=(
            "Signature is authentic and verified"
            if is_valid
            else "Signature verification failed: manifest may have been altered"
        ),
    )
