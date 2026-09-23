"""Unit tests for core/ontology/migration.py."""

from core.ontology.diff import diff_schemas
from core.ontology.migration import _default_value_for_type, generate_migration

# ── Empty diff ────────────────────────────────────────────────────────────


def test_generate_migration_empty_diff_returns_empty() -> None:
    """An empty diff produces no statements."""
    schema = {
        "nodes": {"CVE": {"properties": {"id": {"type": "string", "required": True}}}},
        "relationships": {},
    }
    diff = diff_schemas(schema, schema)
    statements = generate_migration(diff)
    assert statements == []


# ── Added node types ──────────────────────────────────────────────────────


def test_generate_migration_added_node_creates_constraint() -> None:
    """Added node type generates a CREATE CONSTRAINT statement."""
    old = {"nodes": {}, "relationships": {}}
    new = {
        "nodes": {
            "NewType": {
                "description": "x",
                "properties": {"id": {"type": "string", "required": True}},
            }
        },
        "relationships": {},
    }
    diff = diff_schemas(old, new)
    statements = generate_migration(diff)
    combined = "\n".join(statements)
    assert "CREATE CONSTRAINT" in combined
    assert "NewType" in combined


def test_generate_migration_added_node_creates_indexes() -> None:
    """Added node type generates valid_from and source_agent indexes."""
    old = {"nodes": {}, "relationships": {}}
    new = {
        "nodes": {"Widget": {"properties": {}}},
        "relationships": {},
    }
    diff = diff_schemas(old, new)
    statements = generate_migration(diff)
    combined = "\n".join(statements)
    assert "valid_from" in combined
    assert "source_agent" in combined


# ── Removed node types ────────────────────────────────────────────────────


def test_generate_migration_removed_node_has_warning() -> None:
    """Removed node type generates a WARNING comment and DROP CONSTRAINT."""
    old = {
        "nodes": {
            "OldType": {"properties": {"id": {"type": "string", "required": True}}}
        },
        "relationships": {},
    }
    new = {"nodes": {}, "relationships": {}}
    diff = diff_schemas(old, new)
    statements = generate_migration(diff)
    combined = "\n".join(statements)
    assert "WARNING" in combined
    assert "DROP CONSTRAINT" in combined


# ── Added edge types ──────────────────────────────────────────────────────


def test_generate_migration_added_edge_has_comment() -> None:
    """Added edge type generates an informational comment."""
    old = {"nodes": {}, "relationships": {}}
    new = {
        "nodes": {},
        "relationships": {
            "NEW_EDGE": {
                "source_types": ["A"],
                "target_types": ["B"],
                "properties": {},
            }
        },
    }
    diff = diff_schemas(old, new)
    statements = generate_migration(diff)
    combined = "\n".join(statements)
    assert "NEW_EDGE" in combined
    assert "no DDL required" in combined


# ── Removed edge types ────────────────────────────────────────────────────


def test_generate_migration_removed_edge_has_warning() -> None:
    """Removed edge type generates a WARNING comment."""
    old = {
        "nodes": {},
        "relationships": {
            "OLD_EDGE": {"source_types": [], "target_types": [], "properties": {}}
        },
    }
    new = {"nodes": {}, "relationships": {}}
    diff = diff_schemas(old, new)
    statements = generate_migration(diff)
    combined = "\n".join(statements)
    assert "WARNING" in combined
    assert "OLD_EDGE" in combined


# ── Modified node types — new required property ───────────────────────────


def test_generate_migration_new_required_property_sets_default() -> None:
    """New required property on existing node generates a SET default statement."""
    old = {
        "nodes": {"CVE": {"properties": {"id": {"type": "string", "required": True}}}},
        "relationships": {},
    }
    new = {
        "nodes": {
            "CVE": {
                "properties": {
                    "id": {"type": "string", "required": True},
                    "new_required": {"type": "string", "required": True},
                }
            }
        },
        "relationships": {},
    }
    diff = diff_schemas(old, new)
    statements = generate_migration(diff)
    combined = "\n".join(statements)
    assert "new_required" in combined
    assert "SET n.new_required" in combined


def test_generate_migration_new_optional_property_no_set() -> None:
    """New optional property does not generate a SET default statement."""
    old = {"nodes": {"CVE": {"properties": {}}}, "relationships": {}}
    new = {
        "nodes": {
            "CVE": {
                "properties": {"optional_prop": {"type": "string", "required": False}}
            }
        },
        "relationships": {},
    }
    diff = diff_schemas(old, new)
    statements = generate_migration(diff)
    combined = "\n".join(statements)
    assert "SET n.optional_prop" not in combined


# ── Header ────────────────────────────────────────────────────────────────


def test_generate_migration_includes_header_comment() -> None:
    """Non-empty migration always starts with a header comment."""
    old = {"nodes": {}, "relationships": {}}
    new = {"nodes": {"X": {"properties": {}}}, "relationships": {}}
    diff = diff_schemas(old, new)
    statements = generate_migration(diff)
    assert statements[0].startswith("//")
    assert "Migration" in "\n".join(statements[:4])


# ── _default_value_for_type ───────────────────────────────────────────────


def test_default_value_for_string() -> None:
    assert _default_value_for_type("string") == "''"


def test_default_value_for_integer() -> None:
    assert _default_value_for_type("integer") == "0"


def test_default_value_for_float() -> None:
    assert _default_value_for_type("float") == "0.0"


def test_default_value_for_boolean() -> None:
    assert _default_value_for_type("boolean") == "false"


def test_default_value_for_list() -> None:
    assert _default_value_for_type("list") == "[]"


def test_default_value_for_unknown() -> None:
    assert _default_value_for_type("custom_type") == "null"


def test_generate_migration_modified_edge_types() -> None:
    """Modified edge types generate informational review comments."""
    old = {
        "nodes": {},
        "relationships": {
            "COMMUNICATES_WITH": {
                "source_types": ["Malware"],
                "target_types": ["IPAddress"],
                "properties": {"port": {"type": "integer"}},
            }
        },
    }
    new = {
        "nodes": {},
        "relationships": {
            "COMMUNICATES_WITH": {
                "source_types": ["Malware", "Victim"],
                "target_types": ["IPAddress", "Domain"],
                "properties": {
                    "port": {"type": "integer"},
                    "protocol": {"type": "string"},
                },
            }
        },
    }
    diff = diff_schemas(old, new)
    statements = generate_migration(diff)
    combined = "\n".join(statements)
    assert "Modified Relationship Types" in combined
    assert "COMMUNICATES_WITH" in combined
    assert "protocol" in combined
