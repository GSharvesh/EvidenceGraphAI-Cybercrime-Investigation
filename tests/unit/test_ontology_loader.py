"""Unit tests for ontology schema loading."""

from pathlib import Path

import pytest

from core.ontology.loader import OntologyLoader, load_ontology_schema

EXPECTED_NODES = [
    "CVE",
    "Victim",
    "Attacker",
    "Malware",
    "APKSample",
    "Domain",
    "IPAddress",
    "Certificate",
    "ATT&CKTechnique",
    "LogEntry",
    "EvidenceArtifact",
]

EXPECTED_RELATIONSHIPS = [
    "EXPLOITS",
    "DELIVERS",
    "COMMUNICATES_WITH",
    "USES_CERTIFICATE",
    "MAPS_TO",
    "LINKED_CAMPAIGN",
    "DOWNGRADES_TO",
    "DERIVED_FROM",
    "PRECEDES",
    "EXPECTED_TO_LEAD_TO",
    "DETECTED_BY",
    "EXPORTED_AS",
    "HAS_RESPONSE",
    "RESOLVES_TO",
]


def test_load_schema_structure(ontology_loader: OntologyLoader) -> None:
    """Verifies schema.yaml loads with expected keys."""
    schema = ontology_loader.load()
    assert "nodes" in schema
    assert "relationships" in schema
    assert "title" in schema


def test_all_11_node_types_present(ontology_loader: OntologyLoader) -> None:
    """Verifies all 11 node types are defined in ontology."""
    node_types = ontology_loader.node_types
    assert len(node_types) == 11
    for expected_node in EXPECTED_NODES:
        assert expected_node in node_types, f"Missing node type {expected_node}"


def test_all_15_relationship_types_present(ontology_loader: OntologyLoader) -> None:
    """Verifies all 15 relationship types are defined in ontology (14 Phase 0 + SUPERSEDES Phase 1)."""
    rel_types = ontology_loader.relationship_types
    assert len(rel_types) == 15
    for expected_rel in EXPECTED_RELATIONSHIPS:
        assert expected_rel in rel_types, f"Missing relationship type {expected_rel}"
    assert "SUPERSEDES" in rel_types, "Missing SUPERSEDES (Phase 1)"


def test_missing_schema_file_raises() -> None:
    """Verifies FileNotFoundError raised when loading invalid schema path."""
    loader = OntologyLoader(schema_path=Path("non_existent_schema.yaml"))
    with pytest.raises(FileNotFoundError):
        loader.load()


def test_helper_func_load_ontology_schema() -> None:
    """Verifies helper function load_ontology_schema()."""
    schema = load_ontology_schema()
    assert "nodes" in schema
