"""Integration tests for temporal versioning against live Neo4j."""

import time
from datetime import timedelta

from core.graph.client import GraphClient
from core.graph.temporal import now_utc
from tests.integration.conftest import neo4j_required

# All IDs start with TestPhase1_ for isolation
_CVE_ID = "TestPhase1_CVE-2024-TEMPORAL-001"
_ATTACKER_ID = "TestPhase1_Attacker-temporal-001"


@neo4j_required
def test_temporal_fields_set_on_create(
    test_client: GraphClient, clean_test_graph
) -> None:
    """created_at, updated_at, valid_from are set on node creation; valid_to is None."""
    node_id = test_client.create_node(
        "CVE",
        {"id": _CVE_ID, "cvss_score": 9.8, "severity": "CRITICAL"},
    )
    node = test_client.get_node(node_id)
    assert node is not None
    assert node["created_at"] is not None
    assert node["updated_at"] is not None
    assert node["valid_from"] is not None
    assert node["valid_to"] is None


@neo4j_required
def test_update_node_creates_new_version(
    test_client: GraphClient, clean_test_graph
) -> None:
    """update_node creates a new versioned node and SUPERSEDES edge."""
    test_client.create_node(
        "CVE",
        {"id": _CVE_ID, "cvss_score": 7.5, "severity": "HIGH"},
    )
    # Small delay to ensure timestamps differ
    time.sleep(0.05)

    new_id = test_client.update_node(
        _CVE_ID,
        {"cvss_score": 9.8, "severity": "CRITICAL"},
    )

    assert new_id != _CVE_ID
    assert "::v1" in new_id

    # Old node should now have valid_to set
    old = test_client.get_node(_CVE_ID)
    assert old is not None
    assert old["valid_to"] is not None

    # New node should be active (valid_to is None)
    new = test_client.get_node(new_id)
    assert new is not None
    assert new["valid_to"] is None
    assert float(new["cvss_score"]) == 9.8


@neo4j_required
def test_created_at_is_immutable_across_versions(
    test_client: GraphClient, clean_test_graph
) -> None:
    """created_at from the original node is preserved in the new version."""
    test_client.create_node(
        "CVE",
        {"id": _CVE_ID, "cvss_score": 5.0},
    )
    original = test_client.get_node(_CVE_ID)
    original_created_at = original["created_at"]

    time.sleep(0.05)
    new_id = test_client.update_node(_CVE_ID, {"cvss_score": 7.0})
    new_node = test_client.get_node(new_id)

    assert new_node["created_at"] == original_created_at


@neo4j_required
def test_soft_delete_sets_valid_to(test_client: GraphClient, clean_test_graph) -> None:
    """soft_delete sets valid_to without deleting the node."""
    test_client.create_node("CVE", {"id": _CVE_ID, "cvss_score": 9.0})

    deletion_time = now_utc()
    test_client.soft_delete(_CVE_ID, at=deletion_time)

    node = test_client.get_node(_CVE_ID)
    assert node is not None  # not deleted
    assert node["valid_to"] is not None


@neo4j_required
def test_get_node_at_returns_correct_version(
    test_client: GraphClient, clean_test_graph
) -> None:
    """get_node_at returns the version valid at the given timestamp."""
    t_before = now_utc() - timedelta(seconds=2)

    test_client.create_node(
        "CVE",
        {"id": _CVE_ID, "cvss_score": 5.0, "severity": "MEDIUM"},
    )
    t_after_create = now_utc()

    # Before creation, the node should not exist at that time
    assert test_client.get_node_at(_CVE_ID, t_before) is None

    # The original node should be visible just after creation
    result = test_client.get_node_at(_CVE_ID, t_after_create + timedelta(seconds=1))
    assert result is not None


@neo4j_required
def test_get_node_history_returns_all_versions(
    test_client: GraphClient, clean_test_graph
) -> None:
    """get_node_history returns all versions oldest-first."""
    test_client.create_node("CVE", {"id": _CVE_ID, "cvss_score": 1.0})
    time.sleep(0.05)
    v1_id = test_client.update_node(_CVE_ID, {"cvss_score": 2.0})
    time.sleep(0.05)
    test_client.update_node(v1_id, {"cvss_score": 3.0})

    history = test_client.get_node_history(_CVE_ID)
    assert len(history) >= 3  # original + v1 + v2


@neo4j_required
def test_get_latest_version_returns_active_node(
    test_client: GraphClient, clean_test_graph
) -> None:
    """get_latest_version returns the node with valid_to IS NULL."""
    test_client.create_node("CVE", {"id": _CVE_ID, "cvss_score": 1.0})
    time.sleep(0.05)
    new_id = test_client.update_node(_CVE_ID, {"cvss_score": 9.9})

    latest = test_client.get_latest_version(_CVE_ID)
    assert latest is not None
    assert latest["id"] == new_id
    assert float(latest["cvss_score"]) == 9.9


@neo4j_required
def test_soft_delete_edge(test_client: GraphClient, clean_test_graph) -> None:
    """soft_delete_edge sets valid_to on a relationship."""
    test_client.create_node("Attacker", {"id": _ATTACKER_ID, "name": "TempAttacker"})
    test_client.create_node("CVE", {"id": _CVE_ID, "cvss_score": 9.0})
    edge_id = test_client.create_edge(
        _ATTACKER_ID, _CVE_ID, "EXPLOITS", {"vector": "RCE"}
    )

    test_client.soft_delete_edge(edge_id)

    edge = test_client.get_edge(edge_id)
    assert edge is not None
    assert edge["valid_to"] is not None
