"""Integration test against running Neo4j container."""

import pytest

from core.graph.client import GraphClient


def is_neo4j_reachable() -> bool:
    """Helper to verify if local Neo4j container is accepting connections."""
    client = GraphClient()
    return client.health_check()


@pytest.mark.skipif(
    not is_neo4j_reachable(),
    reason="Neo4j container not reachable on bolt://localhost:7687",
)
def test_neo4j_end_to_end_crud() -> None:
    """Performs end-to-end integration test against live Neo4j database."""
    client = GraphClient()
    client.connect()

    attacker_id = "test-attacker-001"
    cve_id = "CVE-2024-7777"

    try:
        # 1. Create Attacker Node
        created_attacker_id = client.create_node(
            node_type="Attacker",
            properties={
                "id": attacker_id,
                "name": "Test APT Group",
                "country_of_origin": "Unknown",
            },
        )
        assert created_attacker_id == attacker_id

        # 2. Create CVE Node
        created_cve_id = client.create_node(
            node_type="CVE",
            properties={"id": cve_id, "cvss_score": 9.8, "severity": "CRITICAL"},
        )
        assert created_cve_id == cve_id

        # 3. Create EXPLOITS Edge
        edge_id = client.create_edge(
            from_id=attacker_id,
            to_id=cve_id,
            edge_type="EXPLOITS",
            properties={"vector": "Remote Code Execution"},
        )
        assert edge_id is not None

        # 4. Query back created nodes and edges
        attacker_data = client.get_node(attacker_id)
        assert attacker_data is not None
        assert attacker_data["name"] == "Test APT Group"
        assert attacker_data["source_agent"] == "system"

        cve_data = client.get_node(cve_id)
        assert cve_data is not None
        assert cve_data["cvss_score"] == 9.8

        edge_data = client.get_edge(edge_id)
        assert edge_data is not None
        assert edge_data["vector"] == "Remote Code Execution"

        # 5. Test Transaction Rollback
        with (
            pytest.raises(RuntimeError),
            client.transaction() as tx,
        ):
            client.create_node(
                "Victim",
                {"id": "rollback-victim", "name": "Rollback Test"},
                tx=tx,
            )
            raise RuntimeError("Trigger rollback")

        rollback_data = client.get_node("rollback-victim")
        assert (
            rollback_data is None
        ), "Node created in failed transaction was not rolled back!"

    finally:
        # Cleanup test data
        client.query(
            "MATCH (n) WHERE n.id IN [$attacker_id, $cve_id] DETACH DELETE n",
            {"attacker_id": attacker_id, "cve_id": cve_id},
        )
        client.close()
