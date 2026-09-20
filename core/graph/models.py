"""Pydantic domain models for EvidenceGraphAI graph nodes and relationships."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field


def current_utc_iso() -> str:
    """Helper to return current UTC ISO timestamp."""
    return datetime.now(UTC).isoformat()


class BaseGraphEntity(BaseModel):
    """Base class containing temporal versioning and provenance tracking fields."""

    # Temporal versioning fields
    valid_from: str = Field(
        default_factory=current_utc_iso, description="Validity start ISO timestamp"
    )
    valid_to: str | None = Field(default=None, description="Validity end ISO timestamp")
    created_at: str = Field(
        default_factory=current_utc_iso, description="Creation ISO timestamp"
    )
    updated_at: str = Field(
        default_factory=current_utc_iso, description="Last updated ISO timestamp"
    )

    # Provenance tracking fields
    source_agent: str = Field(
        default="system", description="Agent responsible for entity creation"
    )
    source_artifact_id: str | None = Field(
        default=None, description="Originating artifact identifier"
    )
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Confidence score [0.0, 1.0]"
    )


class BaseNodeModel(BaseGraphEntity):
    """Base model for all graph nodes."""

    id: str = Field(description="Unique node identifier")


class BaseEdgeModel(BaseGraphEntity):
    """Base model for all graph edges."""

    id: str | None = Field(default=None, description="Unique edge identifier")
    from_id: str = Field(description="Source node ID")
    to_id: str = Field(description="Target node ID")


# --- Node Type Models (11 Node Types) ---


class CVENode(BaseNodeModel):
    cvss_score: float | None = None
    severity: str | None = None
    description: str | None = None


class VictimNode(BaseNodeModel):
    name: str
    sector: str | None = None
    ip_address: str | None = None


class AttackerNode(BaseNodeModel):
    name: str
    aliases: list[str] = Field(default_factory=list)
    country_of_origin: str | None = None


class MalwareNode(BaseNodeModel):
    sha256: str
    family: str | None = None
    malware_type: str | None = None


class APKSampleNode(BaseNodeModel):
    sha256: str
    package_name: str
    app_name: str | None = None
    min_sdk: int | None = None


class DomainNode(BaseNodeModel):
    name: str
    registrar: str | None = None
    created_date: str | None = None


class IPAddressNode(BaseNodeModel):
    addr: str
    asn: int | None = None
    country: str | None = None


class CertificateNode(BaseNodeModel):
    fingerprint: str
    issuer: str | None = None
    subject: str | None = None
    serial_number: str | None = None


class ATTACKTechniqueNode(BaseNodeModel):
    name: str
    tactic: str | None = None


class LogEntryNode(BaseNodeModel):
    timestamp: str
    source: str
    event_id: int | None = None
    message: str | None = None


class EvidenceArtifactNode(BaseNodeModel):
    artifact_type: str
    storage_path: str
    hash_sha256: str


# --- Edge Type Models (14 Relationship Types) ---


class ExploitsEdge(BaseEdgeModel):
    vector: str | None = None


class DeliversEdge(BaseEdgeModel):
    delivery_method: str | None = None


class CommunicatesWithEdge(BaseEdgeModel):
    port: int | None = None
    protocol: str | None = None


class UsesCertificateEdge(BaseEdgeModel):
    validation_status: str | None = None


class MapsToEdge(BaseEdgeModel):
    mapping_confidence: float | None = None


class LinkedCampaignEdge(BaseEdgeModel):
    campaign_name: str | None = None


class DowngradesToEdge(BaseEdgeModel):
    reason: str | None = None


class DerivedFromEdge(BaseEdgeModel):
    extraction_method: str | None = None


class PrecedesEdge(BaseEdgeModel):
    time_delta_ms: int | None = None


class ExpectedToLeadToEdge(BaseEdgeModel):
    probability: float | None = None


class DetectedByEdge(BaseEdgeModel):
    rule_name: str | None = None


class ExportedAsEdge(BaseEdgeModel):
    format: str | None = None


class HasResponseEdge(BaseEdgeModel):
    status: str | None = None


class ResolvesToEdge(BaseEdgeModel):
    resolved_at: str | None = None
