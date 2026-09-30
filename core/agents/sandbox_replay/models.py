"""Pydantic domain models for the Sandbox Replay Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def _now_utc() -> str:
    """Returns current UTC ISO-8601 timestamp."""
    return datetime.now(UTC).isoformat()


class TelemetryArtifact(BaseModel):
    """Represents a telemetry file captured during a sandbox replay."""

    artifact_id: str = Field(description="Evidence artifact ID (from ingestor)")
    path: str = Field(description="Original file path in the sandbox telemetry volume")
    artifact_type: str = Field(description="pcap | text | json")
    sha256: str = Field(description="SHA256 of the artifact")
    size_bytes: int = 0
    captured_at: str = Field(default_factory=_now_utc)


class TechniqueResult(BaseModel):
    """Records whether a hypothesized ATT&CK technique was confirmed or refuted."""

    technique_id: str
    technique_name: str
    status: str = Field(description="confirmed | refuted | inconclusive")
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_artifact_ids: list[str] = Field(default_factory=list)
    rationale: str = ""


class ReplayReport(BaseModel):
    """Summary report produced after a sandbox replay completes."""

    session_id: str
    blueprint_id: str
    cve_id: str
    duration_seconds: float = 0.0
    telemetry_count: int = 0
    confirmed_techniques: list[TechniqueResult] = Field(default_factory=list)
    refuted_techniques: list[TechniqueResult] = Field(default_factory=list)
    inconclusive_techniques: list[TechniqueResult] = Field(default_factory=list)
    attack_mappings: list[dict[str, Any]] = Field(default_factory=list)
    generated_at: str = Field(default_factory=_now_utc)


class ReplaySession(BaseModel):
    """Tracks the lifecycle of a single sandbox replay execution."""

    session_id: str
    blueprint_id: str
    cve_id: str
    status: str = Field(
        default="pending",
        description="pending | running | completed | failed",
    )
    attack_script: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    created_at: str = Field(default_factory=_now_utc)
    telemetry_artifacts: list[TelemetryArtifact] = Field(default_factory=list)
    technique_results: list[TechniqueResult] = Field(default_factory=list)
    report: ReplayReport | None = None
    error_message: str | None = None
