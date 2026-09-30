"""Pydantic domain models for the Threat Reconstruction Agent."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


def _now_utc() -> str:
    """Returns current UTC ISO-8601 timestamp."""
    return datetime.now(UTC).isoformat()


class BlueprintTechnique(BaseModel):
    """A single ATT&CK technique step within a threat blueprint."""

    technique_id: str = Field(description="ATT&CK technique ID e.g. T1190")
    technique_name: str
    tactic: str
    tactic_phase: int = Field(
        description="Ordered phase index (0=initial access, 1=execution, …)"
    )
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence this step occurs")
    status: str = Field(
        default="hypothesized",
        description="Lifecycle status: hypothesized | confirmed | refuted",
    )
    rationale: str = Field(description="Why this step is hypothesized")
    node_id: str = Field(default="", description="Neo4j node ID after graph write")


class BlueprintEdge(BaseModel):
    """A directed edge between two blueprint techniques."""

    from_technique_id: str
    to_technique_id: str
    probability: float = Field(ge=0.0, le=1.0)
    status: str = "hypothesized"
    edge_id: str = Field(default="", description="Neo4j edge ID after graph write")


class Blueprint(BaseModel):
    """Complete hypothetical attack blueprint for a CVE.

    A Blueprint represents the sequence of ATT&CK techniques that an attacker
    would likely execute after exploiting the given CVE, connected by
    ``EXPECTED_TO_LEAD_TO`` edges with ``status: hypothesized``.
    """

    blueprint_id: str = Field(description="Unique blueprint identifier")
    cve_id: str
    techniques: list[BlueprintTechnique] = Field(default_factory=list)
    edges: list[BlueprintEdge] = Field(default_factory=list)
    created_at: str = Field(default_factory=_now_utc)
    source_agent: str = "threat_reconstruction"
    total_confidence: float = Field(
        default=0.0,
        description="Average confidence across all technique steps",
    )
