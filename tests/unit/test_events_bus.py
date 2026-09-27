"""Unit tests for the in-process event bus and publisher subsystem."""

import pytest

from core.events.bus import EventBus, get_event_bus, reset_event_bus
from core.events.publisher import (
    publish_edge_created,
    publish_ledger_entry,
    publish_node_created,
    publish_node_updated,
    publish_status,
)
from core.events.types import (
    EdgeCreatedEvent,
    Event,
    LedgerEntryEvent,
    NodeCreatedEvent,
    NodeUpdatedEvent,
    StatusEvent,
)


@pytest.fixture(autouse=True)
def clean_event_bus() -> None:
    """Ensures a fresh event bus singleton for each test."""
    reset_event_bus()


def test_event_models_creation() -> None:
    """Verifies that all event types can be instantiated with default and custom values."""
    base_evt = Event(event_type="test_base")
    assert base_evt.event_id.startswith("EVT-")
    assert base_evt.event_type == "test_base"
    assert base_evt.timestamp

    ledger_evt = LedgerEntryEvent(
        entry_id=1,
        evidence_id="EV-101",
        action="INGEST",
        actor="forensic_officer",
        sha256="a" * 64,
        previous_hash="0" * 64,
        entry_hash="b" * 64,
        metadata={"filename": "test.pcap"},
    )
    assert ledger_evt.event_type == "ledger_entry"
    assert ledger_evt.evidence_id == "EV-101"

    node_evt = NodeCreatedEvent(
        node_id="CVE-2024-001",
        node_type="CVE",
        properties={"severity": "CRITICAL"},
    )
    assert node_evt.event_type == "node_created"
    assert node_evt.node_type == "CVE"

    edge_evt = EdgeCreatedEvent(
        edge_id="EDGE-1",
        edge_type="EXPLOITS",
        from_id="ATT-1",
        to_id="CVE-1",
    )
    assert edge_evt.event_type == "edge_created"
    assert edge_evt.edge_type == "EXPLOITS"

    updated_evt = NodeUpdatedEvent(
        node_id="CVE-2024-001::v1",
        node_type="CVE",
        properties={"cvss_score": 9.8},
    )
    assert updated_evt.event_type == "node_updated"

    status_evt = StatusEvent(
        neo4j=True,
        postgres=True,
        minio=True,
        redis=True,
        ledger_intact=True,
        ledger_entries=42,
    )
    assert status_evt.event_type == "status"
    assert status_evt.ledger_entries == 42


@pytest.mark.asyncio
async def test_event_bus_publish_subscribe_specific_type() -> None:
    """Verifies subscribing to a specific event type receives matching events only."""
    bus = EventBus()
    q = bus.subscribe_queue(event_type="ledger_entry", maxsize=10)

    # Publish matching event
    matching_evt = LedgerEntryEvent(
        evidence_id="EV-1",
        action="INGEST",
        actor="system",
        sha256="c" * 64,
        previous_hash="0" * 64,
        entry_hash="d" * 64,
    )
    bus.publish(matching_evt)

    # Publish non-matching event
    non_matching_evt = NodeCreatedEvent(
        node_id="N-1",
        node_type="Victim",
        properties={"name": "Org"},
    )
    bus.publish(non_matching_evt)

    # Queue should have received only matching event
    assert q.qsize() == 1
    received = await q.get()
    assert received.event_id == matching_evt.event_id
    assert isinstance(received, LedgerEntryEvent)

    bus.unsubscribe_queue(q, event_type="ledger_entry")
    assert bus.total_subscribers == 0


@pytest.mark.asyncio
async def test_event_bus_wildcard_subscription() -> None:
    """Verifies that a wildcard subscriber (event_type=None) receives all events."""
    bus = EventBus()
    q = bus.subscribe_queue(event_type=None, maxsize=10)

    e1 = LedgerEntryEvent(
        evidence_id="EV-1",
        action="INGEST",
        actor="system",
        sha256="c" * 64,
        previous_hash="0" * 64,
        entry_hash="d" * 64,
    )
    e2 = NodeCreatedEvent(node_id="N-1", node_type="Victim", properties={})

    bus.publish(e1)
    bus.publish(e2)

    assert q.qsize() == 2
    r1 = await q.get()
    r2 = await q.get()
    assert r1.event_id == e1.event_id
    assert r2.event_id == e2.event_id

    bus.unsubscribe_queue(q, event_type=None)


@pytest.mark.asyncio
async def test_event_bus_multiple_subscribers() -> None:
    """Verifies broadcasting to multiple distinct subscribers."""
    bus = EventBus()
    q1 = bus.subscribe_queue(event_type="status")
    q2 = bus.subscribe_queue(event_type="status")
    q3 = bus.subscribe_queue(event_type=None)

    status_evt = StatusEvent(neo4j=True, postgres=True)
    bus.publish(status_evt)

    assert q1.qsize() == 1
    assert q2.qsize() == 1
    assert q3.qsize() == 1

    item1 = await q1.get()
    item2 = await q2.get()
    item3 = await q3.get()

    assert item1.event_id == status_evt.event_id
    assert item2.event_id == status_evt.event_id
    assert item3.event_id == status_evt.event_id


@pytest.mark.asyncio
async def test_event_bus_slow_subscriber_drops_oldest() -> None:
    """Verifies that bounded subscriber queues drop the oldest event when full."""
    bus = EventBus()
    # Capacity = 2
    q = bus.subscribe_queue(event_type="node_created", maxsize=2)

    e1 = NodeCreatedEvent(node_id="N-1", node_type="T", properties={"n": 1})
    e2 = NodeCreatedEvent(node_id="N-2", node_type="T", properties={"n": 2})
    e3 = NodeCreatedEvent(node_id="N-3", node_type="T", properties={"n": 3})

    bus.publish(e1)
    bus.publish(e2)
    assert q.qsize() == 2

    # Third publish should drop e1
    bus.publish(e3)
    assert q.qsize() == 2

    first_received = await q.get()
    second_received = await q.get()

    # e1 was dropped, e2 and e3 remain
    assert first_received.event_id == e2.event_id
    assert second_received.event_id == e3.event_id


@pytest.mark.asyncio
async def test_publisher_functions() -> None:
    """Verifies helper publisher functions publish correctly to the global singleton bus."""
    bus = get_event_bus()
    q = bus.subscribe_queue(event_type=None)

    publish_ledger_entry(
        evidence_id="EV-100",
        action="ANONYMIZE",
        actor="system",
        sha256="1" * 64,
        previous_hash="0" * 64,
        entry_hash="2" * 64,
        entry_id=99,
    )
    publish_node_created("Malware", "MAL-1", {"sha256": "3" * 64})
    publish_edge_created("COMMUNICATES_WITH", "E-1", "MAL-1", "IP-1", {"port": 443})
    publish_node_updated("Malware", "MAL-1::v1", {"family": "Trojan"})
    publish_status(
        neo4j=True,
        postgres=True,
        minio=True,
        redis=True,
        ledger_intact=True,
        ledger_entries=10,
    )

    assert q.qsize() == 5

    evt1 = await q.get()
    assert isinstance(evt1, LedgerEntryEvent)
    assert evt1.evidence_id == "EV-100"
    assert evt1.action == "ANONYMIZE"

    evt2 = await q.get()
    assert isinstance(evt2, NodeCreatedEvent)
    assert evt2.node_id == "MAL-1"

    evt3 = await q.get()
    assert isinstance(evt3, EdgeCreatedEvent)
    assert evt3.edge_type == "COMMUNICATES_WITH"

    evt4 = await q.get()
    assert isinstance(evt4, NodeUpdatedEvent)
    assert evt4.properties["family"] == "Trojan"

    evt5 = await q.get()
    assert isinstance(evt5, StatusEvent)
    assert evt5.ledger_entries == 10
