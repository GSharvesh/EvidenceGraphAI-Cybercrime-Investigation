"""Event publisher helpers used across EvidenceGraphAI subsystems."""

from typing import Any

from core.events.bus import get_event_bus
from core.events.types import (
    EdgeCreatedEvent,
    LedgerEntryEvent,
    NodeCreatedEvent,
    NodeUpdatedEvent,
    StatusEvent,
)
from core.logging.logger import get_logger

logger = get_logger("core.events.publisher")


def publish_ledger_entry(
    evidence_id: str,
    action: str,
    actor: str,
    sha256: str,
    previous_hash: str,
    entry_hash: str,
    metadata: dict[str, Any] | None = None,
    entry_id: int | None = None,
    signature: str | None = None,
    timestamp: str | None = None,
) -> None:
    """Publishes a LedgerEntryEvent to the event bus.

    Args:
        evidence_id: Evidence identifier.
        action: Ledger action type (INGEST, VERIFY, etc.).
        actor: Identity of actor performing the action.
        sha256: Content cryptographic hash.
        previous_hash: Previous block cryptographic hash.
        entry_hash: Block cryptographic hash.
        metadata: Contextual metadata dictionary.
        entry_id: Optional database primary key ID.
        signature: Optional HMAC or digital signature.
        timestamp: Optional ISO-8601 timestamp.
    """
    try:
        kwargs: dict[str, Any] = {
            "evidence_id": evidence_id,
            "action": action,
            "actor": actor,
            "sha256": sha256,
            "previous_hash": previous_hash,
            "entry_hash": entry_hash,
            "metadata": metadata or {},
            "entry_id": entry_id,
            "signature": signature,
        }
        if timestamp:
            kwargs["timestamp"] = timestamp

        event = LedgerEntryEvent(**kwargs)
        get_event_bus().publish(event)
        logger.debug(
            "Published ledger entry event",
            evidence_id=evidence_id,
            action=action,
            entry_hash=entry_hash[:16] + "...",
        )
    except Exception as exc:
        logger.warning("Failed to publish ledger entry event", error=str(exc))


def publish_node_created(
    node_type: str, node_id: str, properties: dict[str, Any]
) -> None:
    """Publishes a NodeCreatedEvent to the event bus."""
    try:
        event = NodeCreatedEvent(
            node_id=node_id,
            node_type=node_type,
            properties=properties,
        )
        get_event_bus().publish(event)
        logger.debug(
            "Published node created event", node_type=node_type, node_id=node_id
        )
    except Exception as exc:
        logger.warning("Failed to publish node created event", error=str(exc))


def publish_edge_created(
    edge_type: str,
    edge_id: str,
    from_id: str,
    to_id: str,
    properties: dict[str, Any] | None = None,
) -> None:
    """Publishes an EdgeCreatedEvent to the event bus."""
    try:
        event = EdgeCreatedEvent(
            edge_id=edge_id,
            edge_type=edge_type,
            from_id=from_id,
            to_id=to_id,
            properties=properties or {},
        )
        get_event_bus().publish(event)
        logger.debug(
            "Published edge created event",
            edge_type=edge_type,
            from_id=from_id,
            to_id=to_id,
        )
    except Exception as exc:
        logger.warning("Failed to publish edge created event", error=str(exc))


def publish_node_updated(
    node_type: str, node_id: str, properties: dict[str, Any]
) -> None:
    """Publishes a NodeUpdatedEvent to the event bus."""
    try:
        event = NodeUpdatedEvent(
            node_id=node_id,
            node_type=node_type,
            properties=properties,
        )
        get_event_bus().publish(event)
        logger.debug(
            "Published node updated event", node_type=node_type, node_id=node_id
        )
    except Exception as exc:
        logger.warning("Failed to publish node updated event", error=str(exc))


def publish_status(
    neo4j: bool,
    postgres: bool,
    minio: bool,
    redis: bool,
    ledger_intact: bool,
    ledger_entries: int,
) -> None:
    """Publishes a StatusEvent representing real-time service health to the event bus."""
    try:
        event = StatusEvent(
            neo4j=neo4j,
            postgres=postgres,
            minio=minio,
            redis=redis,
            ledger_intact=ledger_intact,
            ledger_entries=ledger_entries,
        )
        get_event_bus().publish(event)
        logger.debug(
            "Published status event",
            neo4j=neo4j,
            postgres=postgres,
            minio=minio,
            redis=redis,
            ledger_entries=ledger_entries,
        )
    except Exception as exc:
        logger.warning("Failed to publish status event", error=str(exc))
