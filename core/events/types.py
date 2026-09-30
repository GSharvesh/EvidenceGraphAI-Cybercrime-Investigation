"""Event types and schemas for EvidenceGraphAI pub/sub messaging."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def _now_utc_iso() -> str:
    """Returns current UTC ISO-8601 formatted timestamp string."""
    return datetime.now(UTC).isoformat()


class Event(BaseModel):
    """Base class for all system events."""

    event_id: str = Field(default_factory=lambda: f"EVT-{uuid.uuid4().hex[:12]}")
    event_type: str
    timestamp: str = Field(default_factory=_now_utc_iso)


class LedgerEntryEvent(Event):
    """Event emitted when a new entry is appended to the chain-of-custody ledger."""

    event_type: str = "ledger_entry"
    entry_id: int | None = None
    evidence_id: str
    action: str
    actor: str
    sha256: str
    previous_hash: str
    entry_hash: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    signature: str | None = None


class NodeCreatedEvent(Event):
    """Event emitted when a new node is created in the knowledge graph."""

    event_type: str = "node_created"
    node_id: str
    node_type: str
    properties: dict[str, Any] = Field(default_factory=dict)


class EdgeCreatedEvent(Event):
    """Event emitted when a relationship edge is created between graph nodes."""

    event_type: str = "edge_created"
    edge_id: str
    edge_type: str
    from_id: str
    to_id: str
    properties: dict[str, Any] = Field(default_factory=dict)


class NodeUpdatedEvent(Event):
    """Event emitted when a node is updated via append-only versioning."""

    event_type: str = "node_updated"
    node_id: str
    node_type: str
    properties: dict[str, Any] = Field(default_factory=dict)


class StatusEvent(Event):
    """Event emitted periodically representing real-time system and service health."""

    event_type: str = "status"
    neo4j: bool = False
    postgres: bool = False
    minio: bool = False
    redis: bool = False
    ledger_intact: bool = False
    ledger_entries: int = 0


class CVEAnalyzedEvent(Event):
    """Event emitted when a CVE has been analyzed by the Vulnerability Intelligence Agent."""

    event_type: str = "cve_analyzed"
    cve_id: str
    node_id: str
    cvss_score: float | None = None
    severity: str | None = None
    technique_ids: list[str] = Field(default_factory=list)
    actor: str = "vulnerability_intelligence"


class BlueprintGeneratedEvent(Event):
    """Event emitted when a threat reconstruction blueprint has been generated."""

    event_type: str = "blueprint_generated"
    blueprint_id: str
    cve_id: str
    technique_count: int = 0
    actor: str = "threat_reconstruction"


class ReplaySessionEvent(Event):
    """Event emitted on sandbox replay lifecycle transitions."""

    event_type: str = "replay_session"
    session_id: str
    blueprint_id: str
    cve_id: str
    status: str  # pending, running, completed, failed
    confirmed_count: int = 0
    refuted_count: int = 0
    actor: str = "sandbox_replay"
