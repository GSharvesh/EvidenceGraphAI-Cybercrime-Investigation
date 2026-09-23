"""Unit tests for core/ontology/diff.py."""

from core.ontology.diff import (
    PropertyChange,
    diff_schemas,
)

# ── Fixtures ───────────────────────────────────────────────────────────────


def _base_schema() -> dict:
    return {
        "nodes": {
            "CVE": {
                "description": "Vulnerability record",
                "properties": {
                    "id": {"type": "string", "required": True},
                    "cvss_score": {"type": "float", "required": False},
                },
            },
            "Malware": {
                "description": "Malware entity",
                "properties": {
                    "id": {"type": "string", "required": True},
                    "sha256": {"type": "string", "required": True},
                },
            },
        },
        "relationships": {
            "EXPLOITS": {
                "description": "Exploits a CVE",
                "source_types": ["Attacker"],
                "target_types": ["CVE"],
                "properties": {
                    "vector": {"type": "string", "required": False},
                },
            },
        },
    }


# ── SchemaDiff helpers ────────────────────────────────────────────────────


def test_schema_diff_is_empty_on_identical_schemas() -> None:
    """diff_schemas on identical schemas returns an empty diff."""
    schema = _base_schema()
    diff = diff_schemas(schema, schema)
    assert diff.is_empty


def test_schema_diff_summary_empty() -> None:
    """Empty diff has summary 'No changes'."""
    schema = _base_schema()
    diff = diff_schemas(schema, schema)
    assert diff.summary() == "No changes"


# ── Added node types ──────────────────────────────────────────────────────


def test_added_node_type_detected() -> None:
    """New node type in new_schema appears in added_node_types."""
    old = _base_schema()
    new = _base_schema()
    new["nodes"]["NewEntity"] = {
        "description": "A new entity",
        "properties": {"id": {"type": "string", "required": True}},
    }
    diff = diff_schemas(old, new)
    assert "NewEntity" in diff.added_node_types
    assert not diff.removed_node_types


def test_schema_summary_shows_added_node() -> None:
    """Summary string mentions added node types."""
    old = _base_schema()
    new = _base_schema()
    new["nodes"]["Extra"] = {"properties": {}}
    diff = diff_schemas(old, new)
    assert "node type" in diff.summary()


# ── Removed node types ────────────────────────────────────────────────────


def test_removed_node_type_detected() -> None:
    """Node type removed from new_schema appears in removed_node_types."""
    old = _base_schema()
    new = _base_schema()
    del new["nodes"]["Malware"]
    diff = diff_schemas(old, new)
    assert "Malware" in diff.removed_node_types


# ── Modified node types ───────────────────────────────────────────────────


def test_added_property_detected() -> None:
    """New property on an existing node type is detected."""
    old = _base_schema()
    new = _base_schema()
    new["nodes"]["CVE"]["properties"]["new_prop"] = {
        "type": "string",
        "required": False,
    }
    diff = diff_schemas(old, new)
    assert len(diff.modified_node_types) == 1
    cve_diff = diff.modified_node_types[0]
    assert cve_diff.name == "CVE"
    assert any(p.name == "new_prop" for p in cve_diff.added_properties)


def test_removed_property_detected() -> None:
    """Removed property on an existing node type is detected."""
    old = _base_schema()
    new = _base_schema()
    del new["nodes"]["CVE"]["properties"]["cvss_score"]
    diff = diff_schemas(old, new)
    cve_diff = diff.modified_node_types[0]
    assert any(p.name == "cvss_score" for p in cve_diff.removed_properties)


def test_modified_property_detected() -> None:
    """Changed property definition on an existing node is detected."""
    old = _base_schema()
    new = _base_schema()
    new["nodes"]["CVE"]["properties"]["cvss_score"]["required"] = True  # was False
    diff = diff_schemas(old, new)
    cve_diff = diff.modified_node_types[0]
    assert any(p.name == "cvss_score" for p in cve_diff.modified_properties)


def test_description_change_detected() -> None:
    """Changed description on a node type is flagged."""
    old = _base_schema()
    new = _base_schema()
    new["nodes"]["CVE"]["description"] = "Updated description"
    diff = diff_schemas(old, new)
    assert len(diff.modified_node_types) == 1
    assert diff.modified_node_types[0].description_changed


# ── Added edge types ──────────────────────────────────────────────────────


def test_added_edge_type_detected() -> None:
    """New relationship type in new_schema appears in added_edge_types."""
    old = _base_schema()
    new = _base_schema()
    new["relationships"]["SUPERSEDES"] = {
        "description": "Version supersession",
        "source_types": ["CVE"],
        "target_types": ["CVE"],
        "properties": {},
    }
    diff = diff_schemas(old, new)
    assert "SUPERSEDES" in diff.added_edge_types


# ── Removed edge types ────────────────────────────────────────────────────


def test_removed_edge_type_detected() -> None:
    """Removed relationship type appears in removed_edge_types."""
    old = _base_schema()
    new = _base_schema()
    del new["relationships"]["EXPLOITS"]
    diff = diff_schemas(old, new)
    assert "EXPLOITS" in diff.removed_edge_types


# ── Modified edge types ───────────────────────────────────────────────────


def test_edge_source_types_change_detected() -> None:
    """Changed source_types on an edge type is detected."""
    old = _base_schema()
    new = _base_schema()
    new["relationships"]["EXPLOITS"]["source_types"] = ["Attacker", "Malware"]
    diff = diff_schemas(old, new)
    assert len(diff.modified_edge_types) == 1
    assert diff.modified_edge_types[0].source_types_changed


# ── PropertyChange predicates ─────────────────────────────────────────────


def test_property_change_is_added() -> None:
    """PropertyChange.is_added is True when old_def is None."""
    pc = PropertyChange("p", None, {"type": "string"})
    assert pc.is_added
    assert not pc.is_removed
    assert not pc.is_modified


def test_property_change_is_removed() -> None:
    """PropertyChange.is_removed is True when new_def is None."""
    pc = PropertyChange("p", {"type": "string"}, None)
    assert pc.is_removed


def test_property_change_is_modified() -> None:
    """PropertyChange.is_modified is True when both defs differ."""
    pc = PropertyChange("p", {"type": "string"}, {"type": "integer"})
    assert pc.is_modified
