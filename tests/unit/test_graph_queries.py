"""Unit tests for query builders."""

from core.graph.queries import (
    build_get_edges_by_type_query,
    build_get_neighbors_query,
    build_get_nodes_by_type_query,
)


def test_build_get_nodes_by_type_query() -> None:
    """Verifies build_get_nodes_by_type_query returns Cypher string."""
    cypher, params = build_get_nodes_by_type_query("CVE")
    assert "MATCH (n:`CVE`)" in cypher
    assert params == {}


def test_build_get_edges_by_type_query() -> None:
    """Verifies build_get_edges_by_type_query returns Cypher string."""
    cypher, params = build_get_edges_by_type_query("EXPLOITS")
    assert "MATCH (a)-[r:`EXPLOITS`]->(b)" in cypher
    assert params == {}


def test_build_get_neighbors_query() -> None:
    """Verifies build_get_neighbors_query returns Cypher string with node_id param."""
    cypher, params = build_get_neighbors_query("cve-123")
    assert "MATCH (n {id: $node_id})-[r]-(neighbor)" in cypher
    assert params == {"node_id": "cve-123"}
