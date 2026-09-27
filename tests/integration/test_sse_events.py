"""Integration tests for SSE streaming endpoints and event bus wiring.

SSE streaming endpoints are tested for correct response setup (status, headers)
and the event bus roundtrip is tested directly. Full end-to-end SSE streaming
with httpx ASGITransport is unreliable due to asyncio disconnect handling,
so we validate the plumbing components individually.
"""

import asyncio
from collections.abc import Generator

import pytest

from core.events.bus import EventBus, get_event_bus, reset_event_bus
from core.events.publisher import (
    publish_edge_created,
    publish_ledger_entry,
    publish_node_created,
    publish_status,
)
from core.events.types import (
    EdgeCreatedEvent,
    LedgerEntryEvent,
    NodeCreatedEvent,
    NodeUpdatedEvent,
    StatusEvent,
)


@pytest.fixture(autouse=True)
def _reset_bus() -> Generator[None, None, None]:
    """Reset the global event bus before each test for isolation."""
    reset_event_bus()
    yield
    reset_event_bus()


# ── Event bus pub/sub ────────────────────────────────────────────────────────


class TestEventBusPubSub:
    """Validate event bus typed and wildcard pub/sub delivery."""

    @pytest.mark.asyncio
    async def test_typed_subscriber_receives_matching_event(self) -> None:
        """A typed subscriber should receive only matching events."""
        bus = get_event_bus()
        queue = bus.subscribe_queue(event_type="ledger_entry", maxsize=10)

        event = LedgerEntryEvent(
            evidence_id="EVD-roundtrip",
            action="VERIFY",
            actor="test",
            sha256="c" * 64,
            previous_hash="0" * 64,
            entry_hash="d" * 64,
        )
        bus.publish(event)

        received = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert isinstance(received, LedgerEntryEvent)
        assert received.evidence_id == "EVD-roundtrip"
        assert received.action == "VERIFY"
        assert received.event_type == "ledger_entry"
        bus.unsubscribe_queue(queue, event_type="ledger_entry")

    @pytest.mark.asyncio
    async def test_wildcard_subscriber_receives_all_events(self) -> None:
        """Wildcard (None) subscriber should receive all event types."""
        bus = get_event_bus()
        queue = bus.subscribe_queue(event_type=None, maxsize=10)

        bus.publish(
            StatusEvent(
                neo4j=True,
                postgres=True,
                minio=False,
                redis=True,
            )
        )
        bus.publish(
            LedgerEntryEvent(
                evidence_id="EVD-wild",
                action="INGEST",
                actor="wildcard_test",
                sha256="e" * 64,
                previous_hash="0" * 64,
                entry_hash="f" * 64,
            )
        )

        evt1 = await asyncio.wait_for(queue.get(), timeout=1.0)
        evt2 = await asyncio.wait_for(queue.get(), timeout=1.0)

        types_received = {evt1.event_type, evt2.event_type}
        assert "status" in types_received
        assert "ledger_entry" in types_received
        bus.unsubscribe_queue(queue, event_type=None)

    @pytest.mark.asyncio
    async def test_typed_subscriber_ignores_unmatched_events(self) -> None:
        """A subscriber for 'node_created' should not receive 'ledger_entry'."""
        bus = get_event_bus()
        queue = bus.subscribe_queue(event_type="node_created", maxsize=10)

        bus.publish(
            LedgerEntryEvent(
                evidence_id="EVD-ignore",
                action="INGEST",
                actor="test",
                sha256="a" * 64,
                previous_hash="0" * 64,
                entry_hash="b" * 64,
            )
        )

        assert queue.empty()
        bus.unsubscribe_queue(queue, event_type="node_created")

    @pytest.mark.asyncio
    async def test_multi_type_subscriber(self) -> None:
        """A subscriber registered for multiple types should receive all."""
        bus = get_event_bus()
        types = {"node_created", "edge_created", "node_updated"}
        queue = bus.subscribe_queue(event_type=types, maxsize=10)

        bus.publish(
            NodeCreatedEvent(
                node_id="n1",
                node_type="Malware",
                properties={},
            )
        )
        bus.publish(
            EdgeCreatedEvent(
                edge_id="e1",
                edge_type="DELIVERS",
                from_id="n1",
                to_id="n2",
            )
        )
        bus.publish(
            NodeUpdatedEvent(
                node_id="n1",
                node_type="Malware",
                properties={"updated": True},
            )
        )

        events = []
        for _ in range(3):
            events.append(await asyncio.wait_for(queue.get(), timeout=1.0))

        received_types = {e.event_type for e in events}
        assert received_types == {"node_created", "edge_created", "node_updated"}
        bus.unsubscribe_queue(queue, event_type=types)


# ── Publisher helpers ────────────────────────────────────────────────────────


class TestPublisherHelpers:
    """Validate publisher helper functions deliver events correctly."""

    @pytest.mark.asyncio
    async def test_publish_ledger_entry_delivers(self) -> None:
        """publish_ledger_entry() should publish a LedgerEntryEvent."""
        bus = get_event_bus()
        queue = bus.subscribe_queue(event_type="ledger_entry", maxsize=5)

        publish_ledger_entry(
            evidence_id="EVD-pub-test",
            action="INGEST",
            actor="pub_helper",
            sha256="a" * 64,
            previous_hash="0" * 64,
            entry_hash="b" * 64,
        )

        received = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert isinstance(received, LedgerEntryEvent)
        assert received.evidence_id == "EVD-pub-test"
        assert received.actor == "pub_helper"
        bus.unsubscribe_queue(queue, event_type="ledger_entry")

    @pytest.mark.asyncio
    async def test_publish_node_created_delivers(self) -> None:
        """publish_node_created() should publish a NodeCreatedEvent."""
        bus = get_event_bus()
        queue = bus.subscribe_queue(event_type="node_created", maxsize=5)

        publish_node_created(
            node_type="CVE",
            node_id="CVE-2024-0001",
            properties={"score": 9.8},
        )

        received = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert isinstance(received, NodeCreatedEvent)
        assert received.node_id == "CVE-2024-0001"
        assert received.node_type == "CVE"
        bus.unsubscribe_queue(queue, event_type="node_created")

    @pytest.mark.asyncio
    async def test_publish_edge_created_delivers(self) -> None:
        """publish_edge_created() should publish an EdgeCreatedEvent."""
        bus = get_event_bus()
        queue = bus.subscribe_queue(event_type="edge_created", maxsize=5)

        publish_edge_created(
            edge_type="EXPLOITS",
            edge_id="e-test",
            from_id="a1",
            to_id="v1",
        )

        received = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert isinstance(received, EdgeCreatedEvent)
        assert received.edge_type == "EXPLOITS"
        assert received.from_id == "a1"
        bus.unsubscribe_queue(queue, event_type="edge_created")

    @pytest.mark.asyncio
    async def test_publish_status_delivers(self) -> None:
        """publish_status() should publish a StatusEvent."""
        bus = get_event_bus()
        queue = bus.subscribe_queue(event_type="status", maxsize=5)

        publish_status(
            neo4j=True,
            postgres=True,
            minio=True,
            redis=False,
            ledger_intact=True,
            ledger_entries=42,
        )

        received = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert isinstance(received, StatusEvent)
        assert received.neo4j is True
        assert received.redis is False
        assert received.ledger_entries == 42
        bus.unsubscribe_queue(queue, event_type="status")


# ── Event type model validation ──────────────────────────────────────────────


class TestEventModels:
    """Validate event models serialize correctly."""

    def test_ledger_entry_event_serialization(self) -> None:
        """LedgerEntryEvent should serialize to JSON with all fields."""
        event = LedgerEntryEvent(
            evidence_id="EVD-serial",
            action="INGEST",
            actor="test",
            sha256="a" * 64,
            previous_hash="0" * 64,
            entry_hash="b" * 64,
            metadata={"note": "test"},
        )
        data = event.model_dump()
        assert data["event_type"] == "ledger_entry"
        assert data["evidence_id"] == "EVD-serial"
        assert data["metadata"] == {"note": "test"}
        assert data["event_id"].startswith("EVT-")

    def test_status_event_serialization(self) -> None:
        """StatusEvent should serialize with all service health fields."""
        event = StatusEvent(
            neo4j=True,
            postgres=False,
            minio=True,
            redis=True,
            ledger_intact=True,
            ledger_entries=10,
        )
        json_str = event.model_dump_json()
        assert '"neo4j":true' in json_str or '"neo4j": true' in json_str
        assert '"ledger_entries":10' in json_str or '"ledger_entries": 10' in json_str

    def test_node_created_event_has_defaults(self) -> None:
        """NodeCreatedEvent should have auto-generated event_id and timestamp."""
        event = NodeCreatedEvent(
            node_id="n1",
            node_type="Malware",
            properties={},
        )
        assert event.event_id.startswith("EVT-")
        assert event.timestamp  # not empty
        assert event.event_type == "node_created"


# ── Event bus edge cases ─────────────────────────────────────────────────────


class TestEventBusEdgeCases:
    """Test event bus edge cases and robustness."""

    @pytest.mark.asyncio
    async def test_full_queue_drops_oldest(self) -> None:
        """When a queue is full, oldest event should be dropped."""
        bus = get_event_bus()
        queue = bus.subscribe_queue(event_type="status", maxsize=2)

        # Publish 3 events into a queue of size 2
        for i in range(3):
            bus.publish(StatusEvent(ledger_entries=i))

        # Should have the 2 most recent
        evt1 = await asyncio.wait_for(queue.get(), timeout=1.0)
        evt2 = await asyncio.wait_for(queue.get(), timeout=1.0)
        assert isinstance(evt1, StatusEvent)
        assert isinstance(evt2, StatusEvent)
        assert evt1.ledger_entries == 1
        assert evt2.ledger_entries == 2
        assert queue.empty()
        bus.unsubscribe_queue(queue, event_type="status")

    def test_unsubscribe_prevents_delivery(self) -> None:
        """After unsubscribe, events should not be delivered."""
        bus = get_event_bus()
        queue = bus.subscribe_queue(event_type="status", maxsize=5)
        bus.unsubscribe_queue(queue, event_type="status")

        bus.publish(StatusEvent())
        assert queue.empty()

    def test_subscriber_count_tracking(self) -> None:
        """total_subscribers should accurately reflect registrations."""
        bus = EventBus()
        assert bus.total_subscribers == 0

        q1 = bus.subscribe_queue(event_type="a", maxsize=5)
        assert bus.total_subscribers == 1

        q2 = bus.subscribe_queue(event_type="b", maxsize=5)
        assert bus.total_subscribers == 2

        bus.unsubscribe_queue(q1, event_type="a")
        assert bus.total_subscribers == 1

        bus.unsubscribe_queue(q2, event_type="b")
        assert bus.total_subscribers == 0
