"""Pydantic models for the ATT&CK Mapper."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


def _now_utc() -> str:
    """Returns current UTC ISO-8601 timestamp."""
    return datetime.now(UTC).isoformat()


class MappingResult(BaseModel):
    """A single evidence → ATT&CK technique mapping."""

    evidence_id: str = Field(description="Evidence artifact or log entry ID")
    technique_id: str = Field(description="ATT&CK technique ID e.g. T1059")
    technique_name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)
    rule_name: str = Field(description="Name of the matching rule")
    rationale: str = Field(description="Human-readable match explanation")
    matched_text: str | None = None
    mapped_at: str = Field(default_factory=_now_utc)
    edge_id: str = Field(default="", description="Neo4j MAPS_TO edge ID")
    session_id: str | None = None
