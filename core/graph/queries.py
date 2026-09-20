"""Reusable parameterized Cypher query builders for EvidenceGraphAI."""

from typing import Any


def build_get_nodes_by_type_query(node_type: str) -> tuple[str, dict[str, Any]]:
    """Builds parameterized query to fetch nodes of a given label.

    Args:
        node_type: Node label/type.

    Returns:
        Tuple of (Cypher string, parameters dict).
    """
    query = f"MATCH (n:`{node_type}`) RETURN properties(n) AS properties"
    return query, {}


def build_get_edges_by_type_query(relationship_type: str) -> tuple[str, dict[str, Any]]:
    """Builds parameterized query to fetch relationships of a given type.

    Args:
        relationship_type: Relationship type.

    Returns:
        Tuple of (Cypher string, parameters dict).
    """
    query = (
        f"MATCH (a)-[r:`{relationship_type}`]->(b) "
        f"RETURN r.id AS id, elementId(r) AS element_id, type(r) AS type, "
        f"a.id AS from_id, b.id AS to_id, properties(r) AS properties"
    )
    return query, {}


def build_get_neighbors_query(node_id: str) -> tuple[str, dict[str, Any]]:
    """Builds parameterized query to fetch neighbors of a given node ID.

    Args:
        node_id: Center node identifier.

    Returns:
        Tuple of (Cypher string, parameters dict).
    """
    query = (
        "MATCH (n {id: $node_id})-[r]-(neighbor) "
        "RETURN properties(neighbor) AS neighbor, type(r) AS relationship, properties(r) AS rel_properties"
    )
    return query, {"node_id": node_id}
