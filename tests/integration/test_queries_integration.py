"""Integration tests for QueryLibrary against live Neo4j."""

from core.graph.client import GraphClient
from core.graph.queries import QueryLibrary
from tests.integration.conftest import neo4j_required

# Test node IDs
_CVE_ID = "TestPhase1_CVE-QUERIES-001"
_ATTACKER_ID = "TestPhase1_Attacker-queries-001"
_MALWARE_ID = "TestPhase1_Malware-queries-001"
_VICTIM_ID = "TestPhase1_Victim-queries-001"


def _seed_graph(client: GraphClient) -> dict:
    """Seeds a minimal test graph and returns created IDs."""
    client.create_node(
        "CVE", {"id": _CVE_ID, "cvss_score": 9.8, "severity": "CRITICAL"}
    )
    client.create_node("Attacker", {"id": _ATTACKER_ID, "name": "TestAPT"})
    client.create_node(
        "Malware", {"id": _MALWARE_ID, "sha256": "abc123", "family": "TestWorm"}
    )
    client.create_node("Victim", {"id": _VICTIM_ID, "name": "TestCorp"})

    edge1 = client.create_edge(_ATTACKER_ID, _CVE_ID, "EXPLOITS", {"vector": "RCE"})
    edge2 = client.create_edge(
        _ATTACKER_ID, _MALWARE_ID, "DELIVERS", {"delivery_method": "Phishing"}
    )

    return {"edge1": edge1, "edge2": edge2}


@neo4j_required
def test_get_node_by_id(test_client: GraphClient, clean_test_graph) -> None:
    """get_node_by_id returns correct node."""
    _seed_graph(test_client)
    ql = QueryLibrary(test_client)
    node = ql.get_node_by_id(_CVE_ID)
    assert node is not None
    assert node["id"] == _CVE_ID
    assert float(node["cvss_score"]) == 9.8


@neo4j_required
def test_get_node_by_id_not_found(test_client: GraphClient, clean_test_graph) -> None:
    """get_node_by_id returns None for non-existent node."""
    ql = QueryLibrary(test_client)
    assert ql.get_node_by_id("TestPhase1_nonexistent") is None


@neo4j_required
def test_get_nodes_by_type(test_client: GraphClient, clean_test_graph) -> None:
    """get_nodes_by_type returns nodes of specified label."""
    _seed_graph(test_client)
    ql = QueryLibrary(test_client)
    cves = ql.get_nodes_by_type("CVE")
    ids = [n["id"] for n in cves]
    assert _CVE_ID in ids


@neo4j_required
def test_get_nodes_by_property(test_client: GraphClient, clean_test_graph) -> None:
    """get_nodes_by_property filters by property value."""
    _seed_graph(test_client)
    ql = QueryLibrary(test_client)
    result = ql.get_nodes_by_property("CVE", "severity", "CRITICAL")
    ids = [n["id"] for n in result]
    assert _CVE_ID in ids


@neo4j_required
def test_get_nodes_by_agent(test_client: GraphClient, clean_test_graph) -> None:
    """get_nodes_by_agent returns nodes created by 'system'."""
    _seed_graph(test_client)
    ql = QueryLibrary(test_client)
    nodes = ql.get_nodes_by_agent("system")
    ids = [n["id"] for n in nodes]
    assert _CVE_ID in ids


@neo4j_required
def test_get_edges_from(test_client: GraphClient, clean_test_graph) -> None:
    """get_edges_from returns outgoing edges from a node."""
    _seed_graph(test_client)
    ql = QueryLibrary(test_client)
    edges = ql.get_edges_from(_ATTACKER_ID)
    assert len(edges) >= 2
    to_ids = [e["to_id"] for e in edges]
    assert _CVE_ID in to_ids


@neo4j_required
def test_get_edges_to(test_client: GraphClient, clean_test_graph) -> None:
    """get_edges_to returns incoming edges to a node."""
    _seed_graph(test_client)
    ql = QueryLibrary(test_client)
    edges = ql.get_edges_to(_CVE_ID)
    assert len(edges) >= 1
    assert any(e["from_id"] == _ATTACKER_ID for e in edges)


@neo4j_required
def test_get_neighbors(test_client: GraphClient, clean_test_graph) -> None:
    """get_neighbors returns connected nodes and edges."""
    _seed_graph(test_client)
    ql = QueryLibrary(test_client)
    result = ql.get_neighbors(_ATTACKER_ID, depth=1)
    assert "nodes" in result
    assert "edges" in result
    neighbor_ids = [n["id"] for n in result["nodes"]]
    assert _CVE_ID in neighbor_ids or _MALWARE_ID in neighbor_ids


@neo4j_required
def test_count_nodes_by_type(test_client: GraphClient, clean_test_graph) -> None:
    """count_nodes_by_type returns non-zero counts after seeding."""
    _seed_graph(test_client)
    ql = QueryLibrary(test_client)
    counts = ql.count_nodes_by_type()
    assert counts.get("CVE", 0) >= 1
    assert counts.get("Attacker", 0) >= 1


@neo4j_required
def test_count_edges_by_type(test_client: GraphClient, clean_test_graph) -> None:
    """count_edges_by_type returns non-zero counts after seeding."""
    _seed_graph(test_client)
    ql = QueryLibrary(test_client)
    counts = ql.count_edges_by_type()
    assert counts.get("EXPLOITS", 0) >= 1


@neo4j_required
def test_get_graph_statistics_keys(test_client: GraphClient, clean_test_graph) -> None:
    """get_graph_statistics returns expected keys."""
    _seed_graph(test_client)
    ql = QueryLibrary(test_client)
    stats = ql.get_graph_statistics()
    assert "node_counts" in stats
    assert "edge_counts" in stats
    assert "totals" in stats
    assert stats["totals"]["nodes"] > 0


@neo4j_required
def test_get_nodes_by_source_artifact(
    test_client: GraphClient, clean_test_graph
) -> None:
    """get_nodes_by_source_artifact filters by source_artifact_id."""
    test_client.create_node(
        "CVE",
        {
            "id": _CVE_ID,
            "cvss_score": 9.8,
            "source_agent": "system",
            "source_artifact_id": "artifact-test-001",
            "confidence": 0.9,
        },
    )
    ql = QueryLibrary(test_client)
    nodes = ql.get_nodes_by_source_artifact("artifact-test-001")
    assert any(n["id"] == _CVE_ID for n in nodes)


@neo4j_required
def test_find_shortest_path(test_client: GraphClient, clean_test_graph) -> None:
    """find_shortest_path finds a path when one exists."""
    _seed_graph(test_client)
    ql = QueryLibrary(test_client)
    path = ql.find_shortest_path(_ATTACKER_ID, _CVE_ID)
    assert path is not None
    assert _ATTACKER_ID in path
    assert _CVE_ID in path
