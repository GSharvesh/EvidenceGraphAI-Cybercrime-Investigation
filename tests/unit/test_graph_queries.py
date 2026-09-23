"""Unit tests for the Phase 1 QueryLibrary (22 methods) using mocked GraphClient."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from core.graph.exceptions import GraphQueryError
from core.graph.queries import QueryLibrary


def _make_ql(mock_query_result: list | None = None) -> tuple[QueryLibrary, MagicMock]:
    """Helper: creates a QueryLibrary with a mocked GraphClient."""
    client = MagicMock()
    if mock_query_result is not None:
        client.query.return_value = mock_query_result
    ql = QueryLibrary(client)
    return ql, client


# ── Node Retrieval ─────────────────────────────────────────────────────────


def test_get_node_by_id_delegates_to_client() -> None:
    """get_node_by_id delegates to client.get_node."""
    ql, client = _make_ql()
    client.get_node.return_value = {"id": "cve-1", "severity": "HIGH"}
    result = ql.get_node_by_id("cve-1")
    client.get_node.assert_called_once_with("cve-1")
    assert result == {"id": "cve-1", "severity": "HIGH"}


def test_get_node_by_id_not_found() -> None:
    """get_node_by_id returns None when client returns None."""
    ql, client = _make_ql()
    client.get_node.return_value = None
    assert ql.get_node_by_id("missing") is None


def test_get_nodes_by_type_returns_list() -> None:
    """get_nodes_by_type returns list of property dicts."""
    ql, client = _make_ql(
        [
            {"props": {"id": "cve-1"}},
            {"props": {"id": "cve-2"}},
        ]
    )
    result = ql.get_nodes_by_type("CVE")
    assert len(result) == 2
    assert result[0]["id"] == "cve-1"


def test_get_nodes_by_type_empty() -> None:
    """get_nodes_by_type returns empty list when no nodes found."""
    ql, client = _make_ql([])
    assert ql.get_nodes_by_type("CVE") == []


def test_get_nodes_by_property() -> None:
    """get_nodes_by_property passes property/value as params."""
    ql, client = _make_ql([{"props": {"id": "ip-1", "addr": "1.2.3.4"}}])
    result = ql.get_nodes_by_property("IPAddress", "addr", "1.2.3.4")
    assert len(result) == 1
    call_params = client.query.call_args[0][1]
    assert call_params["prop"] == "addr"
    assert call_params["value"] == "1.2.3.4"


def test_get_nodes_by_agent() -> None:
    """get_nodes_by_agent filters by source_agent."""
    ql, client = _make_ql([{"props": {"id": "n-1", "source_agent": "system"}}])
    result = ql.get_nodes_by_agent("system")
    assert len(result) == 1
    call_params = client.query.call_args[0][1]
    assert call_params["agent"] == "system"


# ── Edge Retrieval ─────────────────────────────────────────────────────────


def test_get_edge_by_id_delegates_to_client() -> None:
    """get_edge_by_id delegates to client.get_edge."""
    ql, client = _make_ql()
    client.get_edge.return_value = {"id": "e-1"}
    result = ql.get_edge_by_id("e-1")
    client.get_edge.assert_called_once_with("e-1")
    assert result == {"id": "e-1"}


def test_get_edges_by_type_returns_records() -> None:
    """get_edges_by_type returns raw query records."""
    records = [{"id": "e-1", "from_id": "a-1", "to_id": "c-1", "type": "EXPLOITS"}]
    ql, client = _make_ql(records)
    result = ql.get_edges_by_type("EXPLOITS")
    assert result == records


def test_get_edges_from_no_type_filter() -> None:
    """get_edges_from without type filter uses open-ended Cypher."""
    ql, client = _make_ql([])
    ql.get_edges_from("node-1")
    cypher = client.query.call_args[0][0]
    assert "MATCH (a {id: $node_id})-[r]->(b)" in cypher


def test_get_edges_from_with_type_filter() -> None:
    """get_edges_from with edge_type uses typed Cypher."""
    ql, client = _make_ql([])
    ql.get_edges_from("node-1", edge_type="EXPLOITS")
    cypher = client.query.call_args[0][0]
    assert "EXPLOITS" in cypher


def test_get_edges_to_no_type_filter() -> None:
    """get_edges_to without type filter uses open-ended Cypher."""
    ql, client = _make_ql([])
    ql.get_edges_to("node-1")
    cypher = client.query.call_args[0][0]
    assert "WHERE b.id = $node_id" in cypher


def test_get_edges_to_with_type_filter() -> None:
    """get_edges_to with edge_type uses typed Cypher."""
    ql, client = _make_ql([])
    ql.get_edges_to("node-1", edge_type="EXPLOITS")
    cypher = client.query.call_args[0][0]
    assert "EXPLOITS" in cypher


# ── Neighborhood ──────────────────────────────────────────────────────────


def test_get_neighbors_returns_nodes_and_edges() -> None:
    """get_neighbors returns dict with nodes and edges keys."""
    records = [
        {
            "from_props": {"id": "a-1"},
            "to_props": {"id": "b-1"},
            "edge_type": "EXPLOITS",
            "edge_id": "e-1",
            "edge_props": {},
        }
    ]
    ql, client = _make_ql(records)
    result = ql.get_neighbors("a-1")
    assert "nodes" in result
    assert "edges" in result
    assert len(result["edges"]) == 1


def test_get_subgraph_uses_node_ids_param() -> None:
    """get_subgraph passes node_ids list as param."""
    ql, client = _make_ql([])
    ql.get_subgraph(["n-1", "n-2"])
    call_params = client.query.call_args[0][1]
    assert call_params["node_ids"] == ["n-1", "n-2"]


# ── Temporal ──────────────────────────────────────────────────────────────


def test_get_nodes_at_delegates_to_client() -> None:
    """get_nodes_at delegates to client.get_nodes_valid_at."""
    ql, client = _make_ql()
    client.get_nodes_valid_at.return_value = [{"id": "n-1"}]
    ts = datetime(2024, 1, 1, tzinfo=UTC)
    result = ql.get_nodes_at(ts, node_type="CVE")
    client.get_nodes_valid_at.assert_called_once_with(ts, node_type="CVE")
    assert result == [{"id": "n-1"}]


def test_get_edges_at_constructs_temporal_filter() -> None:
    """get_edges_at includes temporal filter in Cypher."""
    ql, client = _make_ql([])
    ts = datetime(2024, 6, 1, tzinfo=UTC)
    ql.get_edges_at(ts)
    cypher = client.query.call_args[0][0]
    assert "valid_from" in cypher
    assert "valid_to" in cypher


def test_get_node_history_delegates_to_client() -> None:
    """get_node_history delegates to client.get_node_history."""
    ql, client = _make_ql()
    client.get_node_history.return_value = [{"id": "n-1"}, {"id": "n-1::v2"}]
    result = ql.get_node_history("n-1")
    client.get_node_history.assert_called_once_with("n-1")
    assert len(result) == 2


def test_get_latest_version_delegates_to_client() -> None:
    """get_latest_version delegates to client.get_latest_version."""
    ql, client = _make_ql()
    client.get_latest_version.return_value = {"id": "n-1::v2"}
    result = ql.get_latest_version("n-1")
    client.get_latest_version.assert_called_once_with("n-1")
    assert result == {"id": "n-1::v2"}


# ── Provenance ────────────────────────────────────────────────────────────


def test_get_nodes_by_source_artifact_passes_param() -> None:
    """get_nodes_by_source_artifact uses artifact_id as param."""
    ql, client = _make_ql([{"props": {"id": "n-1"}}])
    result = ql.get_nodes_by_source_artifact("artifact-999")
    call_params = client.query.call_args[0][1]
    assert call_params["artifact_id"] == "artifact-999"
    assert len(result) == 1


def test_get_full_provenance_chain_empty_graph() -> None:
    """get_full_provenance_chain returns empty list when no DERIVED_FROM edges."""
    ql, client = _make_ql([])
    result = ql.get_full_provenance_chain("n-1")
    assert result == []


def test_get_full_provenance_chain_with_ancestors() -> None:
    """get_full_provenance_chain strips the start node from results."""
    ql, client = _make_ql(
        [{"chain": [{"id": "n-1"}, {"id": "artifact-1"}, {"id": "artifact-root"}]}]
    )
    result = ql.get_full_provenance_chain("n-1")
    # Should NOT include the first node (the start node itself)
    assert len(result) == 2
    assert result[0]["id"] == "artifact-1"


# ── Aggregate ─────────────────────────────────────────────────────────────


def test_count_nodes_by_type_returns_dict() -> None:
    """count_nodes_by_type returns {label: count} dict."""
    ql, client = _make_ql(
        [
            {"label": "CVE", "cnt": 5},
            {"label": "Malware", "cnt": 3},
        ]
    )
    result = ql.count_nodes_by_type()
    assert result == {"CVE": 5, "Malware": 3}


def test_count_edges_by_type_returns_dict() -> None:
    """count_edges_by_type returns {type: count} dict."""
    ql, client = _make_ql([{"rel_type": "EXPLOITS", "cnt": 10}])
    result = ql.count_edges_by_type()
    assert result == {"EXPLOITS": 10}


def test_get_graph_statistics_structure() -> None:
    """get_graph_statistics returns expected keys."""
    ql, client = _make_ql()
    # Mock the three internal calls
    with (
        patch.object(ql, "count_nodes_by_type", return_value={"CVE": 2}),
        patch.object(ql, "count_edges_by_type", return_value={"EXPLOITS": 1}),
    ):
        client.query.return_value = [{"cnt": 2}]
        stats = ql.get_graph_statistics()
    assert "node_counts" in stats
    assert "edge_counts" in stats
    assert "totals" in stats
    assert "active_node_count" in stats


# ── Path Finding ──────────────────────────────────────────────────────────


def test_find_shortest_path_returns_list() -> None:
    """find_shortest_path returns list of node IDs when path exists."""
    ql, client = _make_ql([{"ids": ["a", "b", "c"]}])
    result = ql.find_shortest_path("a", "c")
    assert result == ["a", "b", "c"]


def test_find_shortest_path_returns_none_when_no_path() -> None:
    """find_shortest_path returns None when query returns no results."""
    ql, client = _make_ql([])
    result = ql.find_shortest_path("a", "z")
    assert result is None


def test_find_all_paths_returns_list_of_lists() -> None:
    """find_all_paths returns a list of path lists."""
    ql, client = _make_ql(
        [
            {"ids": ["a", "b", "c"]},
            {"ids": ["a", "x", "c"]},
        ]
    )
    result = ql.find_all_paths("a", "c")
    assert len(result) == 2
    assert result[0] == ["a", "b", "c"]


# ── Attack Lifecycle ──────────────────────────────────────────────────────


def test_get_attack_lifecycle_returns_nodes_and_edges() -> None:
    """get_attack_lifecycle returns nodes and edges dict."""
    ql, client = _make_ql(
        [
            {
                "from_props": {"id": "attacker-1"},
                "to_props": {"id": "cve-log4shell"},
                "edge_type": "EXPLOITS",
                "edge_id": "e-1",
                "edge_props": {},
            }
        ]
    )
    result = ql.get_attack_lifecycle("cve-log4shell")
    assert "nodes" in result
    assert "edges" in result


def test_get_campaign_links_returns_records() -> None:
    """get_campaign_links passes case_id as param."""
    records = [{"id": "e-1", "from_id": "a-1", "to_id": "a-2"}]
    ql, client = _make_ql(records)
    result = ql.get_campaign_links("attacker-1")
    call_params = client.query.call_args[0][1]
    assert call_params["case_id"] == "attacker-1"
    assert result == records


def test_get_timeline_orders_by_timestamp() -> None:
    """get_timeline returns props sorted by timestamp (Cypher ORDER BY)."""
    ql, client = _make_ql(
        [
            {"props": {"id": "log-1", "timestamp": "2024-01-01T00:00:00"}},
            {"props": {"id": "log-2", "timestamp": "2024-01-02T00:00:00"}},
        ]
    )
    result = ql.get_timeline("victim-1")
    assert len(result) == 2


# ── Error propagation ─────────────────────────────────────────────────────


def test_query_error_propagates_from_get_nodes_by_type() -> None:
    """GraphQueryError raised inside get_nodes_by_type propagates up."""
    ql, client = _make_ql()
    client.query.side_effect = GraphQueryError("boom")
    with pytest.raises(GraphQueryError):
        ql.get_nodes_by_type("CVE")


def test_unexpected_error_wrapped_by_get_nodes_by_agent() -> None:
    """Non-GraphQueryError from client is wrapped as GraphQueryError."""
    ql, client = _make_ql()
    client.query.side_effect = RuntimeError("unexpected")
    with pytest.raises(GraphQueryError, match="get_nodes_by_agent failed"):
        ql.get_nodes_by_agent("system")


def test_query_error_paths() -> None:
    """Test error handling in remaining QueryLibrary methods."""
    ql, client = _make_ql()
    client.query.side_effect = RuntimeError("db down")
    client.get_nodes_valid_at.side_effect = RuntimeError("db down")

    with pytest.raises(GraphQueryError):
        ql.get_nodes_by_property("CVE", "severity", "HIGH")

    with pytest.raises(GraphQueryError):
        ql.get_edges_by_type("EXPLOITS")

    with pytest.raises(GraphQueryError):
        ql.get_edges_from("node1")

    with pytest.raises(GraphQueryError):
        ql.get_edges_to("node2")

    with pytest.raises(GraphQueryError):
        ql.get_neighbors("node1")

    with pytest.raises(GraphQueryError):
        ql.get_subgraph(["node1"])

    with pytest.raises(GraphQueryError):
        ql.get_edges_at(datetime.now(UTC))

    with pytest.raises(GraphQueryError):
        ql.get_nodes_by_source_artifact("art1")

    with pytest.raises(GraphQueryError):
        ql.get_full_provenance_chain("node1")

    with pytest.raises(GraphQueryError):
        ql.count_nodes_by_type()

    with pytest.raises(GraphQueryError):
        ql.count_edges_by_type()

    with pytest.raises(GraphQueryError):
        ql.get_graph_statistics()

    with pytest.raises(GraphQueryError):
        ql.find_shortest_path("a", "b")

    with pytest.raises(GraphQueryError):
        ql.find_all_paths("a", "b")

    with pytest.raises(GraphQueryError):
        ql.get_attack_lifecycle("cve1")

    with pytest.raises(GraphQueryError):
        ql.get_campaign_links("c1")

    with pytest.raises(GraphQueryError):
        ql.get_timeline("v1")
