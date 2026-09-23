"""Unit tests for core/ontology/introspection.py."""

from core.ontology.introspection import (
    get_allowed_sources,
    get_allowed_targets,
    get_edge_type_schema,
    get_node_type_schema,
    list_edge_types,
    list_node_types,
    list_properties,
    list_required_properties,
)
from core.ontology.loader import load_ontology_schema

# Load the actual schema once for all tests
_SCHEMA = load_ontology_schema()


# ── list_node_types ────────────────────────────────────────────────────────


def test_list_node_types_returns_list() -> None:
    """list_node_types returns a non-empty sorted list."""
    types = list_node_types(_SCHEMA)
    assert isinstance(types, list)
    assert len(types) > 0


def test_list_node_types_contains_expected() -> None:
    """list_node_types includes all 11 Phase 0 node types."""
    types = list_node_types(_SCHEMA)
    for expected in [
        "CVE",
        "Victim",
        "Attacker",
        "Malware",
        "APKSample",
        "Domain",
        "IPAddress",
        "Certificate",
        "LogEntry",
        "EvidenceArtifact",
    ]:
        assert expected in types, f"Missing node type: {expected}"


def test_list_node_types_is_sorted() -> None:
    """list_node_types returns types in alphabetical order."""
    types = list_node_types(_SCHEMA)
    assert types == sorted(types)


def test_list_node_types_empty_schema() -> None:
    """list_node_types on empty schema returns empty list."""
    assert list_node_types({}) == []


# ── list_edge_types ────────────────────────────────────────────────────────


def test_list_edge_types_returns_list() -> None:
    """list_edge_types returns a non-empty sorted list."""
    types = list_edge_types(_SCHEMA)
    assert isinstance(types, list)
    assert len(types) > 0


def test_list_edge_types_contains_supersedes() -> None:
    """list_edge_types includes SUPERSEDES (Phase 1 addition)."""
    types = list_edge_types(_SCHEMA)
    assert "SUPERSEDES" in types


def test_list_edge_types_count() -> None:
    """list_edge_types returns 15 relationship types (14 Phase 0 + 1 Phase 1)."""
    types = list_edge_types(_SCHEMA)
    assert len(types) == 15, f"Expected 15, got {len(types)}: {types}"


# ── get_node_type_schema ───────────────────────────────────────────────────


def test_get_node_type_schema_returns_dict() -> None:
    """get_node_type_schema returns a dict for a known type."""
    schema = get_node_type_schema(_SCHEMA, "CVE")
    assert isinstance(schema, dict)
    assert "properties" in schema


def test_get_node_type_schema_unknown_type_returns_empty() -> None:
    """get_node_type_schema returns empty dict for unknown type."""
    result = get_node_type_schema(_SCHEMA, "UNKNOWN_TYPE")
    assert result == {}


def test_get_node_type_schema_does_not_mutate() -> None:
    """get_node_type_schema returns a copy, not the original dict."""
    s1 = get_node_type_schema(_SCHEMA, "CVE")
    s1["injected"] = True
    s2 = get_node_type_schema(_SCHEMA, "CVE")
    assert "injected" not in s2


# ── get_edge_type_schema ───────────────────────────────────────────────────


def test_get_edge_type_schema_returns_dict() -> None:
    """get_edge_type_schema returns a dict for a known type."""
    schema = get_edge_type_schema(_SCHEMA, "EXPLOITS")
    assert "source_types" in schema
    assert "target_types" in schema


def test_get_edge_type_schema_unknown_returns_empty() -> None:
    """get_edge_type_schema returns empty dict for unknown type."""
    assert get_edge_type_schema(_SCHEMA, "FAKE_EDGE") == {}


# ── list_properties ────────────────────────────────────────────────────────


def test_list_properties_cve() -> None:
    """list_properties returns CVE properties including required ones."""
    props = list_properties(_SCHEMA, "CVE")
    assert "id" in props
    assert "cvss_score" in props


def test_list_properties_is_sorted() -> None:
    """list_properties returns properties in alphabetical order."""
    props = list_properties(_SCHEMA, "Malware")
    assert props == sorted(props)


def test_list_properties_unknown_type_returns_empty() -> None:
    """list_properties returns empty list for unknown node type."""
    assert list_properties(_SCHEMA, "UNKNOWN") == []


# ── list_required_properties ──────────────────────────────────────────────


def test_list_required_properties_cve() -> None:
    """list_required_properties returns 'id' for CVE (the only required field)."""
    required = list_required_properties(_SCHEMA, "CVE")
    assert "id" in required


def test_list_required_properties_victim() -> None:
    """list_required_properties returns id and name for Victim."""
    required = list_required_properties(_SCHEMA, "Victim")
    assert "id" in required
    assert "name" in required


def test_list_required_properties_unknown_type_empty() -> None:
    """list_required_properties returns empty list for unknown type."""
    assert list_required_properties(_SCHEMA, "UNKNOWN") == []


# ── get_allowed_sources / get_allowed_targets ─────────────────────────────


def test_get_allowed_sources_exploits() -> None:
    """EXPLOITS allows Attacker and Malware as sources."""
    sources = get_allowed_sources(_SCHEMA, "EXPLOITS")
    assert "Attacker" in sources
    assert "Malware" in sources


def test_get_allowed_targets_exploits() -> None:
    """EXPLOITS allows only CVE as target."""
    targets = get_allowed_targets(_SCHEMA, "EXPLOITS")
    assert targets == ["CVE"]


def test_get_allowed_sources_unknown_edge_empty() -> None:
    """Unknown edge type returns empty source list."""
    assert get_allowed_sources(_SCHEMA, "FAKE") == []


def test_get_allowed_targets_supersedes() -> None:
    """SUPERSEDES allows all 11 node types as targets."""
    targets = get_allowed_targets(_SCHEMA, "SUPERSEDES")
    assert len(targets) == 11
