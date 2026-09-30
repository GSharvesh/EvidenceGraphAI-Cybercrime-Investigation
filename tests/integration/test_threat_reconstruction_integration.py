"""Integration tests for Threat Reconstruction Agent against Neo4j."""

from __future__ import annotations

import pytest

from core.agents.threat_reconstruction.agent import ThreatReconstructionAgent
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
def test_threat_reconstruction_end_to_end(clean_test_graph) -> None:
    graph = GraphClient()

    # Pre-seed a CVE node
    cve_id = "TESTPHASE3_CVE-2021-44228"
    graph.create_node(
        node_type="CVE",
        properties={
            "id": cve_id,
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "description": "Log4j Remote Code Execution vulnerability",
        },
    )

    tr_agent = ThreatReconstructionAgent(graph_client=graph)
    blueprint = tr_agent.blueprint(cve_id=cve_id, actor="threat_reconstruction")

    assert blueprint.cve_id == cve_id
    assert len(blueprint.techniques) > 0
    assert len(blueprint.edges) > 0
    assert blueprint.total_confidence > 0.0

    # Verify EXPECTED_TO_LEAD_TO edges materialized
    from core.graph.queries import QueryLibrary

    ql = QueryLibrary(graph)
    edges = ql.get_edges_by_type(edge_type="EXPECTED_TO_LEAD_TO")
    assert len(edges) > 0
