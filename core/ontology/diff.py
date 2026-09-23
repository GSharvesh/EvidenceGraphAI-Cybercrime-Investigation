"""Schema diffing utilities for EvidenceGraphAI ontology.

Compares two versions of the ontology schema and produces a structured
:class:`SchemaDiff` describing what changed.  This diff can then be fed
into :func:`~core.ontology.migration.generate_migration` to produce
Cypher migration statements.

Example::

    from core.ontology.loader import OntologyLoader
    from core.ontology.diff import diff_schemas

    old_schema = OntologyLoader("schema_v1.yaml").load()
    new_schema = OntologyLoader("schema_v2.yaml").load()
    diff = diff_schemas(old_schema, new_schema)
    print(diff.added_node_types)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PropertyChange:
    """Describes a change to a single property definition."""

    name: str
    old_def: dict[str, Any] | None
    new_def: dict[str, Any] | None

    @property
    def is_added(self) -> bool:
        """True when this property is newly added."""
        return self.old_def is None and self.new_def is not None

    @property
    def is_removed(self) -> bool:
        """True when this property is removed."""
        return self.old_def is not None and self.new_def is None

    @property
    def is_modified(self) -> bool:
        """True when the property definition changed."""
        return (
            self.old_def is not None
            and self.new_def is not None
            and self.old_def != self.new_def
        )


@dataclass
class NodeTypeDiff:
    """Describes changes to a single node type."""

    name: str
    added_properties: list[PropertyChange] = field(default_factory=list)
    removed_properties: list[PropertyChange] = field(default_factory=list)
    modified_properties: list[PropertyChange] = field(default_factory=list)
    description_changed: bool = False


@dataclass
class EdgeTypeDiff:
    """Describes changes to a single relationship type."""

    name: str
    added_properties: list[PropertyChange] = field(default_factory=list)
    removed_properties: list[PropertyChange] = field(default_factory=list)
    modified_properties: list[PropertyChange] = field(default_factory=list)
    source_types_changed: bool = False
    target_types_changed: bool = False


@dataclass
class SchemaDiff:
    """The result of comparing two schema versions."""

    # Node type changes
    added_node_types: list[str] = field(default_factory=list)
    removed_node_types: list[str] = field(default_factory=list)
    modified_node_types: list[NodeTypeDiff] = field(default_factory=list)

    # Edge type changes
    added_edge_types: list[str] = field(default_factory=list)
    removed_edge_types: list[str] = field(default_factory=list)
    modified_edge_types: list[EdgeTypeDiff] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """True if no changes were detected."""
        return not (
            self.added_node_types
            or self.removed_node_types
            or self.modified_node_types
            or self.added_edge_types
            or self.removed_edge_types
            or self.modified_edge_types
        )

    def summary(self) -> str:
        """Returns a human-readable one-line summary."""
        parts: list[str] = []
        if self.added_node_types:
            parts.append(f"+{len(self.added_node_types)} node type(s)")
        if self.removed_node_types:
            parts.append(f"-{len(self.removed_node_types)} node type(s)")
        if self.modified_node_types:
            parts.append(f"~{len(self.modified_node_types)} node type(s) modified")
        if self.added_edge_types:
            parts.append(f"+{len(self.added_edge_types)} edge type(s)")
        if self.removed_edge_types:
            parts.append(f"-{len(self.removed_edge_types)} edge type(s)")
        if self.modified_edge_types:
            parts.append(f"~{len(self.modified_edge_types)} edge type(s) modified")
        return ", ".join(parts) if parts else "No changes"


def diff_schemas(old_schema: dict[str, Any], new_schema: dict[str, Any]) -> SchemaDiff:
    """Compares two ontology schema dictionaries and returns a :class:`SchemaDiff`.

    Args:
        old_schema: Previous schema version (loaded from ``schema.yaml``).
        new_schema: New schema version.

    Returns:
        A :class:`SchemaDiff` describing all additions, removals, and
        modifications at the node type, edge type, and property levels.
    """
    diff = SchemaDiff()

    old_nodes: dict[str, Any] = old_schema.get("nodes", {})
    new_nodes: dict[str, Any] = new_schema.get("nodes", {})

    # Node types
    diff.added_node_types = sorted(set(new_nodes) - set(old_nodes))
    diff.removed_node_types = sorted(set(old_nodes) - set(new_nodes))

    for name in sorted(set(old_nodes) & set(new_nodes)):
        node_diff = _diff_node_type(name, old_nodes[name], new_nodes[name])
        if (
            node_diff.added_properties
            or node_diff.removed_properties
            or node_diff.modified_properties
            or node_diff.description_changed
        ):
            diff.modified_node_types.append(node_diff)

    old_rels: dict[str, Any] = old_schema.get("relationships", {})
    new_rels: dict[str, Any] = new_schema.get("relationships", {})

    # Edge types
    diff.added_edge_types = sorted(set(new_rels) - set(old_rels))
    diff.removed_edge_types = sorted(set(old_rels) - set(new_rels))

    for name in sorted(set(old_rels) & set(new_rels)):
        edge_diff = _diff_edge_type(name, old_rels[name], new_rels[name])
        if (
            edge_diff.added_properties
            or edge_diff.removed_properties
            or edge_diff.modified_properties
            or edge_diff.source_types_changed
            or edge_diff.target_types_changed
        ):
            diff.modified_edge_types.append(edge_diff)

    return diff


def _diff_node_type(
    name: str, old_def: dict[str, Any], new_def: dict[str, Any]
) -> NodeTypeDiff:
    node_diff = NodeTypeDiff(name=name)
    if old_def.get("description") != new_def.get("description"):
        node_diff.description_changed = True

    old_props: dict[str, Any] = old_def.get("properties", {})
    new_props: dict[str, Any] = new_def.get("properties", {})

    for prop_name in sorted(set(new_props) - set(old_props)):
        node_diff.added_properties.append(
            PropertyChange(name=prop_name, old_def=None, new_def=new_props[prop_name])
        )
    for prop_name in sorted(set(old_props) - set(new_props)):
        node_diff.removed_properties.append(
            PropertyChange(name=prop_name, old_def=old_props[prop_name], new_def=None)
        )
    for prop_name in sorted(set(old_props) & set(new_props)):
        if old_props[prop_name] != new_props[prop_name]:
            node_diff.modified_properties.append(
                PropertyChange(
                    name=prop_name,
                    old_def=old_props[prop_name],
                    new_def=new_props[prop_name],
                )
            )
    return node_diff


def _diff_edge_type(
    name: str, old_def: dict[str, Any], new_def: dict[str, Any]
) -> EdgeTypeDiff:
    edge_diff = EdgeTypeDiff(name=name)
    if old_def.get("source_types") != new_def.get("source_types"):
        edge_diff.source_types_changed = True
    if old_def.get("target_types") != new_def.get("target_types"):
        edge_diff.target_types_changed = True

    old_props: dict[str, Any] = old_def.get("properties", {})
    new_props: dict[str, Any] = new_def.get("properties", {})

    for prop_name in sorted(set(new_props) - set(old_props)):
        edge_diff.added_properties.append(
            PropertyChange(name=prop_name, old_def=None, new_def=new_props[prop_name])
        )
    for prop_name in sorted(set(old_props) - set(new_props)):
        edge_diff.removed_properties.append(
            PropertyChange(name=prop_name, old_def=old_props[prop_name], new_def=None)
        )
    for prop_name in sorted(set(old_props) & set(new_props)):
        if old_props[prop_name] != new_props[prop_name]:
            edge_diff.modified_properties.append(
                PropertyChange(
                    name=prop_name,
                    old_def=old_props[prop_name],
                    new_def=new_props[prop_name],
                )
            )
    return edge_diff
