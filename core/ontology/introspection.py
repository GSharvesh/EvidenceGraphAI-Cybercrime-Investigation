"""Schema introspection utilities for EvidenceGraphAI ontology.

These functions operate on a loaded schema dictionary (from
:func:`~core.ontology.loader.load_ontology_schema`) and have no Neo4j
dependency.

Example::

    from core.ontology.loader import load_ontology_schema
    from core.ontology.introspection import list_node_types, get_node_type_schema

    schema = load_ontology_schema()
    print(list_node_types(schema))
    print(get_node_type_schema(schema, "CVE"))
"""

from typing import Any


def list_node_types(schema: dict[str, Any]) -> list[str]:
    """Returns the names of all node types defined in the schema.

    Args:
        schema: Loaded ontology schema dictionary.

    Returns:
        Sorted list of node type name strings.
    """
    return sorted(schema.get("nodes", {}).keys())


def list_edge_types(schema: dict[str, Any]) -> list[str]:
    """Returns the names of all relationship types defined in the schema.

    Args:
        schema: Loaded ontology schema dictionary.

    Returns:
        Sorted list of relationship type name strings.
    """
    return sorted(schema.get("relationships", {}).keys())


def get_node_type_schema(schema: dict[str, Any], node_type: str) -> dict[str, Any]:
    """Returns the full schema definition for a node type.

    Args:
        schema: Loaded ontology schema dictionary.
        node_type: Node type name (e.g. ``"CVE"``).

    Returns:
        Schema dict for the node type, or an empty dict if not found.
    """
    return dict(schema.get("nodes", {}).get(node_type, {}))


def get_edge_type_schema(schema: dict[str, Any], edge_type: str) -> dict[str, Any]:
    """Returns the full schema definition for a relationship type.

    Args:
        schema: Loaded ontology schema dictionary.
        edge_type: Relationship type name (e.g. ``"EXPLOITS"``).

    Returns:
        Schema dict for the relationship type, or an empty dict if not found.
    """
    return dict(schema.get("relationships", {}).get(edge_type, {}))


def list_properties(schema: dict[str, Any], node_type: str) -> list[str]:
    """Returns the property names defined for a node type.

    Args:
        schema: Loaded ontology schema dictionary.
        node_type: Node type name.

    Returns:
        Sorted list of property name strings.
    """
    node_def = schema.get("nodes", {}).get(node_type, {})
    return sorted(node_def.get("properties", {}).keys())


def list_required_properties(schema: dict[str, Any], node_type: str) -> list[str]:
    """Returns property names marked ``required: true`` for a node type.

    Args:
        schema: Loaded ontology schema dictionary.
        node_type: Node type name.

    Returns:
        Sorted list of required property name strings.
    """
    node_def = schema.get("nodes", {}).get(node_type, {})
    props = node_def.get("properties", {})
    return sorted(k for k, v in props.items() if v.get("required", False))


def get_allowed_sources(schema: dict[str, Any], edge_type: str) -> list[str]:
    """Returns the allowed source node types for a relationship type.

    Args:
        schema: Loaded ontology schema dictionary.
        edge_type: Relationship type name.

    Returns:
        List of allowed source node type names.
    """
    rel_def = schema.get("relationships", {}).get(edge_type, {})
    return list(rel_def.get("source_types", []))


def get_allowed_targets(schema: dict[str, Any], edge_type: str) -> list[str]:
    """Returns the allowed target node types for a relationship type.

    Args:
        schema: Loaded ontology schema dictionary.
        edge_type: Relationship type name.

    Returns:
        List of allowed target node type names.
    """
    rel_def = schema.get("relationships", {}).get(edge_type, {})
    return list(rel_def.get("target_types", []))
