"""Validator for checking node and edge properties against the ontology schema."""

from typing import Any

from core.graph.exceptions import GraphValidationError
from core.ontology.loader import OntologyLoader


class OntologyValidator:
    """Validates node and edge properties against the ontology schema."""

    def __init__(self, loader: OntologyLoader | None = None) -> None:
        self.loader = loader or OntologyLoader()
        self.schema = self.loader.load()

    def validate_node(self, node_type: str, properties: dict[str, Any]) -> None:
        """Validates node type and properties.

        Args:
            node_type: Target node type (e.g. CVE, Malware).
            properties: Properties dictionary to validate.

        Raises:
            GraphValidationError: If node_type is unknown or required property is missing.
        """
        nodes_schema = self.schema.get("nodes", {})
        if node_type not in nodes_schema:
            raise GraphValidationError(
                f"Unknown node type '{node_type}'. Valid types: {list(nodes_schema.keys())}"
            )

        node_def = nodes_schema[node_type]
        allowed_props = node_def.get("properties", {})

        # Check required fields
        for prop_name, prop_def in allowed_props.items():
            if prop_def.get("required", False) and prop_name not in properties:
                raise GraphValidationError(
                    f"Missing required property '{prop_name}' for node type '{node_type}'"
                )

    def validate_edge(self, edge_type: str, properties: dict[str, Any]) -> None:
        """Validates edge type and properties.

        Args:
            edge_type: Target relationship type (e.g. EXPLOITS, COMMUNICATES_WITH).
            properties: Properties dictionary to validate.

        Raises:
            GraphValidationError: If edge_type is unknown.
        """
        rel_schema = self.schema.get("relationships", {})
        if edge_type not in rel_schema:
            raise GraphValidationError(
                f"Unknown relationship type '{edge_type}'. Valid types: {list(rel_schema.keys())}"
            )

        rel_def = rel_schema[edge_type]
        allowed_props = rel_def.get("properties", {})

        for prop_name, prop_def in allowed_props.items():
            if prop_def.get("required", False) and prop_name not in properties:
                raise GraphValidationError(
                    f"Missing required property '{prop_name}' for relationship type '{edge_type}'"
                )
