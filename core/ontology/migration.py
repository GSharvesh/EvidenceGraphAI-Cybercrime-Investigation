"""Cypher migration statement generator for EvidenceGraphAI schema changes.

Accepts a :class:`~core.ontology.diff.SchemaDiff` and produces a list of
Cypher statements that, when executed in order, migrate a Neo4j database
from the old schema to the new schema.

The caller is responsible for executing the statements via
:meth:`~core.graph.client.GraphClient.query`.

Statements generated:
- ``CREATE CONSTRAINT`` for new node types (uniqueness on ``id``).
- ``DROP CONSTRAINT`` for removed node types.
- ``CREATE INDEX`` for new node types (``valid_from``, ``source_agent``).
- Property default set statements for new required properties on existing nodes.
- Comments marking additions, removals, and modifications.

Example::

    from core.ontology.diff import diff_schemas
    from core.ontology.migration import generate_migration

    diff = diff_schemas(old_schema, new_schema)
    statements = generate_migration(diff)
    for stmt in statements:
        client.query(stmt)
"""

from core.ontology.diff import SchemaDiff


def generate_migration(diff: SchemaDiff) -> list[str]:
    """Generates Cypher migration statements from a :class:`SchemaDiff`.

    The returned list contains executable Cypher statements in the correct
    execution order.  Statements are idempotent where possible (using
    ``IF NOT EXISTS`` / ``IF EXISTS``).

    Args:
        diff: A :class:`SchemaDiff` produced by :func:`~core.ontology.diff.diff_schemas`.

    Returns:
        List of Cypher statement strings.  May be empty if the diff is empty.
    """
    statements: list[str] = []

    if diff.is_empty:
        return statements

    statements.append("// ============================================================")
    statements.append("// EvidenceGraphAI Schema Migration — Generated Cypher")
    statements.append("// Review each statement before executing in production.")
    statements.append("// ============================================================")

    # -----------------------------------------------------------------
    # Added node types → CREATE CONSTRAINT + CREATE INDEX
    # -----------------------------------------------------------------
    if diff.added_node_types:
        statements.append("")
        statements.append("// --- Added Node Types ---")
        for node_type in diff.added_node_types:
            safe = node_type.replace("&", "").replace(" ", "_").lower()
            statements.append(
                f"CREATE CONSTRAINT {safe}_id_unique IF NOT EXISTS "
                f"FOR (n:`{node_type}`) REQUIRE n.id IS UNIQUE;"
            )
            statements.append(
                f"CREATE INDEX {safe}_valid_from_idx IF NOT EXISTS "
                f"FOR (n:`{node_type}`) ON (n.valid_from);"
            )
            statements.append(
                f"CREATE INDEX {safe}_source_agent_idx IF NOT EXISTS "
                f"FOR (n:`{node_type}`) ON (n.source_agent);"
            )

    # -----------------------------------------------------------------
    # Removed node types → DROP CONSTRAINT + warning comment
    # -----------------------------------------------------------------
    if diff.removed_node_types:
        statements.append("")
        statements.append("// --- Removed Node Types (REVIEW BEFORE EXECUTING) ---")
        for node_type in diff.removed_node_types:
            safe = node_type.replace("&", "").replace(" ", "_").lower()
            statements.append(
                f"// WARNING: Removing constraint for '{node_type}'. "
                f"Ensure all nodes of this type are migrated or deleted first."
            )
            statements.append(f"DROP CONSTRAINT {safe}_id_unique IF EXISTS;")

    # -----------------------------------------------------------------
    # Modified node types → property defaults for new required props
    # -----------------------------------------------------------------
    if diff.modified_node_types:
        statements.append("")
        statements.append("// --- Modified Node Types ---")
        for node_diff in diff.modified_node_types:
            for prop_change in node_diff.added_properties:
                if prop_change.new_def and prop_change.new_def.get("required", False):
                    prop_name = prop_change.name
                    prop_type = prop_change.new_def.get("type", "string")
                    default_val = _default_value_for_type(prop_type)
                    statements.append(
                        f"// Set default for new required property '{prop_name}' "
                        f"on existing {node_diff.name} nodes."
                    )
                    statements.append(
                        f"MATCH (n:`{node_diff.name}`) "
                        f"WHERE n.{prop_name} IS NULL "
                        f"SET n.{prop_name} = {default_val};"
                    )

    # -----------------------------------------------------------------
    # Added edge types → comment only (no DDL for relationships needed)
    # -----------------------------------------------------------------
    if diff.added_edge_types:
        statements.append("")
        statements.append("// --- Added Relationship Types ---")
        for edge_type in diff.added_edge_types:
            statements.append(
                f"// Relationship type '{edge_type}' added — no DDL required."
            )

    # -----------------------------------------------------------------
    # Removed edge types → warning comment
    # -----------------------------------------------------------------
    if diff.removed_edge_types:
        statements.append("")
        statements.append(
            "// --- Removed Relationship Types (REVIEW BEFORE EXECUTING) ---"
        )
        for edge_type in diff.removed_edge_types:
            statements.append(
                f"// WARNING: Relationship type '{edge_type}' removed from schema. "
                f"Remove existing instances if appropriate:"
            )
            statements.append(f"// MATCH ()-[r:`{edge_type}`]->() DELETE r;")

    # -----------------------------------------------------------------
    # Modified edge types
    # -----------------------------------------------------------------
    if diff.modified_edge_types:
        statements.append("")
        statements.append("// --- Modified Relationship Types ---")
        for edge_diff in diff.modified_edge_types:
            if edge_diff.source_types_changed or edge_diff.target_types_changed:
                statements.append(
                    f"// Relationship '{edge_diff.name}' allowed types changed — "
                    f"review existing instances for compliance."
                )
            for prop_change in edge_diff.added_properties:
                statements.append(
                    f"// New property '{prop_change.name}' added to '{edge_diff.name}'."
                )

    return statements


def _default_value_for_type(schema_type: str) -> str:
    """Returns a Cypher literal default value for a schema property type.

    Args:
        schema_type: Schema type string (``"string"``, ``"integer"``, etc.).

    Returns:
        Cypher literal string.
    """
    defaults: dict[str, str] = {
        "string": "''",
        "integer": "0",
        "float": "0.0",
        "boolean": "false",
        "list": "[]",
    }
    return defaults.get(schema_type, "null")
